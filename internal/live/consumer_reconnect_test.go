// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package live_test

// This test runs the real go-rabbitmq client against a real broker: a dropped
// connection must re-establish the consumer in place, with no process
// restart. Set RABBITMQ_TEST_URL to a broker to run it; it skips otherwise.

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Bugs5382/go-rabbitmq"
	auditv1 "github.com/Steward-GRC/steward-gateway/gen/go/thirdparty/audit/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Steward-GRC/steward-gateway/internal/live"
)

func brokerURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("RABBITMQ_TEST_URL")
	if u == "" {
		t.Skip("set RABBITMQ_TEST_URL (broker with default_queue_type=quorum) to run live consumer integration tests")
	}
	return u
}

// TestRunConsumerSurvivesConnectionDrop is the point of the whole adoption: a
// broker connection drop must re-establish the consumer in place, with no
// process restart and no caller-owned re-dial loop.
//
// The consumer's Conn is dialled through an in-process TCP proxy so the test can
// sever the connection the way a broker restart does, without touching the
// broker (the publisher uses a direct connection and stays up throughout). A
// second event delivered after the cut proves the library re-declared the
// ephemeral queue under its NEW server-assigned name, re-bound it and resumed
// consuming.
func TestRunConsumerSurvivesConnectionDrop(t *testing.T) {
	rawURL := brokerURL(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy := newTCPProxy(t, rawURL)
	defer proxy.Close()

	// Fast, deterministic backoff so the test does not wait on the 500ms/30s
	// production curve. MaxRetries stays 0 (retry forever) — bounding it is the
	// defect being retired.
	consumerConn, err := rabbitmq.Connect(ctx, proxy.URL(),
		rabbitmq.WithBackoff(rabbitmq.Backoff{Initial: 50 * time.Millisecond, Max: 250 * time.Millisecond, Jitter: 0}),
		rabbitmq.WithLogger(testLogger{t: t}),
	)
	if err != nil {
		t.Fatalf("connect consumer: %v", err)
	}
	defer func() { _ = consumerConn.Close() }()

	bus := live.NewBus()
	events, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	var wg sync.WaitGroup
	wg.Go(func() {
		// RunConsumer is started ONCE. If it returns before ctx is cancelled the
		// library failed to own reconnect, which is precisely the regression.
		if err := live.RunConsumer(ctx, consumerConn, bus, log.Nop()); err != nil && ctx.Err() == nil {
			t.Errorf("RunConsumer returned early (reconnect is supposed to be owned by the Conn): %v", err)
		}
	})

	// Publisher on a direct connection so cutting the proxy does not disturb it.
	pubConn, err := rabbitmq.Connect(ctx, rawURL)
	if err != nil {
		t.Fatalf("connect publisher: %v", err)
	}
	defer func() { _ = pubConn.Close() }()
	pub := pubConn.NewPublisher(live.Exchange,
		rabbitmq.WithExchangeDeclare(rabbitmq.ExchangeConfig{Name: live.Exchange, Kind: "topic", Durable: true}))

	// Before the drop.
	awaitEvent(t, ctx, pub, events, "policy.published.before")

	before := consumerConn.Reconnects()

	// Sever every proxied socket — what a broker restart looks like to a client.
	proxy.CutAll()

	// The Conn's monitor must observe the close and re-dial on its own.
	deadline := time.Now().Add(30 * time.Second)
	for consumerConn.Reconnects() <= before || !consumerConn.Healthy() {
		if time.Now().After(deadline) {
			t.Fatalf("connection did not recover: reconnects=%d healthy=%t",
				consumerConn.Reconnects(), consumerConn.Healthy())
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("reconnected: reconnects=%d healthy=%t", consumerConn.Reconnects(), consumerConn.Healthy())

	// Drain anything buffered from before the cut so the next assertion can only
	// pass on a genuinely re-established consumer.
	for draining := true; draining; {
		select {
		case <-events:
		default:
			draining = false
		}
	}

	// After the drop: a fresh event must still reach the bus. This only works if
	// the consumer re-declared its (new) server-named queue, re-bound it to the
	// audit exchange and resumed consuming.
	awaitEvent(t, ctx, pub, events, "policy.published.after")

	cancel()
	wg.Wait()
}

// awaitEvent publishes an audit envelope carrying action and waits for it to
// surface on the bus. It retries the publish because the consumer's binding is
// re-established asynchronously after a reconnect, so the first event or two can
// legitimately be published before the new binding exists.
func awaitEvent(t *testing.T, ctx context.Context, pub *rabbitmq.Publisher, events <-chan live.Event, action string) {
	t.Helper()
	body, err := proto.Marshal(&auditv1.AuditEvent{
		Tier: auditv1.Tier_TIER_AUDIT, Action: action, ActorUserId: "tester", Subject: "pol-1", GroupId: "grp-1",
		OccurredAt: timestamppb.New(time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := pub.Publish(ctx, "audit.audit", body); err != nil {
			t.Fatalf("publish %s: %v", action, err)
		}
		select {
		case ev := <-events:
			if ev.Type != action {
				continue // a straggler from an earlier publish; keep waiting
			}
			if ev.EntityID != "pol-1" || ev.GroupID != "grp-1" || ev.ActorUserID != "tester" {
				t.Fatalf("envelope decoded wrong: %+v", ev)
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatalf("event %q never reached the bus", action)
}

// testLogger routes the library's log output into the test log, so a failure
// shows the actual reconnect sequence.
type testLogger struct{ t *testing.T }

func (l testLogger) Debugf(string, ...any)     {}
func (l testLogger) Infof(f string, a ...any)  { l.t.Logf("rabbitmq INFO: "+f, a...) }
func (l testLogger) Warnf(f string, a ...any)  { l.t.Logf("rabbitmq WARN: "+f, a...) }
func (l testLogger) Errorf(f string, a ...any) { l.t.Logf("rabbitmq ERROR: "+f, a...) }

// tcpProxy forwards AMQP traffic to the real broker and can sever every
// connection it has opened, which is how this test simulates a broker drop
// without restarting the broker.
type tcpProxy struct {
	t        *testing.T
	ln       net.Listener
	backend  string
	proxyURL string

	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func newTCPProxy(t *testing.T, brokerURL string) *tcpProxy {
	t.Helper()
	u, err := url.Parse(brokerURL)
	if err != nil {
		t.Fatalf("parse RABBITMQ_TEST_URL: %v", err)
	}
	backend := u.Host
	if u.Port() == "" {
		backend = net.JoinHostPort(u.Hostname(), "5672")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Rewrite only the host, preserving credentials and the vhost path.
	pu := *u
	pu.Host = ln.Addr().String()

	p := &tcpProxy{t: t, ln: ln, backend: backend, proxyURL: pu.String()}
	go p.serve()
	return p
}

func (p *tcpProxy) URL() string { return p.proxyURL }

func (p *tcpProxy) serve() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		upstream, err := net.Dial("tcp", p.backend)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.track(client, upstream)
		go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
		go func() { _, _ = io.Copy(client, upstream); _ = client.Close() }()
	}
}

func (p *tcpProxy) track(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		for _, c := range cs {
			_ = c.Close()
		}
		return
	}
	p.conns = append(p.conns, cs...)
}

// CutAll closes every tracked socket, so both the client and the broker see an
// abrupt transport failure.
func (p *tcpProxy) CutAll() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *tcpProxy) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	_ = p.ln.Close()
	p.CutAll()
}
