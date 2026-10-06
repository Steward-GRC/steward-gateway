// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package aijobs

import (
	"context"
	"encoding/json"

	"github.com/Bugs5382/go-rabbitmq"
)

const (
	// Exchange is the topic exchange the ai operator publishes completions to.
	Exchange = "ai.jobs"
	// BindingKey binds both outcomes, ai.job.succeeded and ai.job.failed.
	BindingKey = "ai.job.*"
)

// Consume binds an ephemeral per-replica queue to Exchange and hands each
// completion to broker. Each replica gets its own server-named queue, so every
// replica sees every completion. go-rabbitmq reconnects and re-binds in
// place: Consume returns only when ctx ends or the connection is closed, and
// the caller must not wrap it in a retry loop.
func Consume(ctx context.Context, conn *rabbitmq.Conn, broker *Broker) error {
	return conn.Consume(ctx, rabbitmq.ConsumerConfig{
		Exchange: rabbitmq.ExchangeConfig{Name: Exchange, Kind: "topic", Durable: true},
		Queue: rabbitmq.QueueConfig{
			Name:       "",
			Type:       rabbitmq.QueueClassic,
			AutoDelete: true,
			Exclusive:  true,
		}.Transient(),
		Bindings: []rabbitmq.BindingConfig{
			{Exchange: Exchange, RoutingKey: BindingKey},
		},
		AutoAck:   true,
		Exclusive: true,
	}, func(_ context.Context, d rabbitmq.Delivery) error {
		var ev CompletionEvent
		if err := json.Unmarshal(d.Body, &ev); err != nil || ev.JobID == "" {
			return nil
		}
		broker.Publish(ev)
		return nil
	})
}
