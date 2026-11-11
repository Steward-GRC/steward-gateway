// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package config

// WorkloadTokenFile is where the charts mount the gateway's projected
// service-account token, used when WORKLOAD_TOKEN_FILE is unset.
// go-workload-identity carries no product defaults, so the service supplies it.
const WorkloadTokenFile = "/var/run/secrets/steward/token" // #nosec G101 -- a file path, not a credential
