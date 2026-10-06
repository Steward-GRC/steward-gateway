// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package config reads every gateway setting from the environment once, at
// start-up, and validates it. No other package reads the environment.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Steward-GRC/steward-gateway/internal/backend"
	"github.com/Steward-GRC/steward-gateway/internal/workloadauth"
)

// Config is the gateway's settings.
type Config struct {
	// HTTPAddr is the listen address of the browser-facing edge.
	HTTPAddr string
	// Backends maps each service name to its host:port.
	Backends map[string]string
	// WorkloadAuth is false only for WORKLOAD_AUTH=disabled, on local runs.
	WorkloadAuth bool
	// TokenFile is the gateway's projected service-account token, sent on
	// every backend call; empty when WorkloadAuth is off.
	TokenFile string

	ValkeyAddr     string
	ValkeyPassword string
	SessionTTL     time.Duration
	// RabbitMQURL feeds live updates and AI job results; empty turns both off.
	RabbitMQURL string

	KratosPublicURL string
	KratosAdminURL  string
	// PolisURL is Polis's in-cluster address; empty means no SSO.
	PolisURL string

	CollabUpstream        string
	AllowedOrigins        []string
	CollabMaxMessageBytes int64
	CollabIdleTimeout     time.Duration

	AllowTemplateDelete bool
	Playground          bool

	// Release is the pinned release version (STEWARD_RELEASE).
	Release string
	// ApplianceVersionFile is set only on the appliance.
	ApplianceVersionFile string
	// HTTPProbes are probe-only components (name to health URL) the
	// diagnostics read lists with the services.
	HTTPProbes map[string]string
	// KubernetesAPI is the in-cluster API address, empty outside a cluster.
	KubernetesAPI string

	// Auth holds the sign-in settings.
	Auth Auth
}

// Auth is the session and sign-in settings.
type Auth struct{}

// Load reads and validates the settings.
func Load(getenv func(string) string) (Config, error) {
	or := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	var errs []error
	duration := func(k string, def time.Duration) time.Duration {
		v := getenv(k)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("config: %s=%q is not a positive duration", k, v))
			return def
		}
		return d
	}
	c := Config{
		HTTPAddr:             or("GATEWAY_HTTP_ADDR", ":8080"),
		Backends:             map[string]string{},
		ValkeyAddr:           or("VALKEY_ADDR", "steward-valkey:6379"),
		ValkeyPassword:       getenv("VALKEY_PASSWORD"),
		SessionTTL:           duration("SESSION_TTL", 168*time.Hour),
		RabbitMQURL:          getenv("RABBITMQ_URL"),
		KratosPublicURL:      or("KRATOS_PUBLIC_URL", "http://steward-kratos:4433"),
		KratosAdminURL:       or("KRATOS_ADMIN_URL", "http://steward-kratos:4434"),
		PolisURL:             getenv("POLIS_URL"),
		CollabUpstream:       or("COLLAB_WS_UPSTREAM", "steward-collab:8081"),
		AllowedOrigins:       list(getenv("ALLOWED_ORIGINS")),
		CollabIdleTimeout:    duration("COLLAB_WS_IDLE_TIMEOUT", 120*time.Second),
		AllowTemplateDelete:  getenv("STEWARD_ALLOW_TEMPLATE_DELETE") == "true",
		Playground:           getenv("GRAPHQL_PLAYGROUND") == "true",
		Release:              getenv("STEWARD_RELEASE"),
		ApplianceVersionFile: getenv("STEWARD_APPLIANCE_VERSION_FILE"),
		HTTPProbes:           map[string]string{},
	}
	for _, n := range backend.Names() {
		c.Backends[n] = or("STEWARD_"+strings.ToUpper(n)+"_ADDR", "steward-"+n+":9090")
	}
	if v := getenv("COLLAB_WS_MAX_MESSAGE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("config: COLLAB_WS_MAX_MESSAGE_BYTES=%q is not a positive number", v))
		}
		c.CollabMaxMessageBytes = n
	}
	for _, kv := range list(getenv("DIAGNOSTICS_HTTP_PROBES")) {
		name, url, ok := strings.Cut(kv, "=")
		if !ok || name == "" || url == "" {
			errs = append(errs, fmt.Errorf("config: DIAGNOSTICS_HTTP_PROBES entry %q must be name=url", kv))
			continue
		}
		c.HTTPProbes[name] = url
	}
	if h := getenv("KUBERNETES_SERVICE_HOST"); h != "" {
		c.KubernetesAPI = "https://" + h + ":" + or("KUBERNETES_SERVICE_PORT", "443")
	}

	switch mode := getenv(workloadauth.EnvAuthMode); mode {
	case "":
		c.WorkloadAuth = true
		c.TokenFile = or(workloadauth.EnvTokenFile, workloadauth.DefaultTokenFile)
		if _, err := os.Stat(c.TokenFile); err != nil {
			errs = append(errs, fmt.Errorf("config: the workload token %s is unreadable; mount it, or set %s=%s for local development only",
				workloadauth.EnvTokenFile, workloadauth.EnvAuthMode, workloadauth.AuthDisabled))
		}
	case workloadauth.AuthDisabled:
	default:
		errs = append(errs, fmt.Errorf("config: %s=%q: the only accepted value is %q", workloadauth.EnvAuthMode, mode, workloadauth.AuthDisabled))
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}

func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
