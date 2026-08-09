package server

import (
	"context"
	"net"
	"testing"
	"time"

	aegisv1 "github.com/apexguard/apexguard/core/gen"
	"github.com/apexguard/apexguard/core/internal/bus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const bufSize = 1 << 20

func newTestServer(t *testing.T) (aegisv1.AegisCoreClient, func()) {
	t.Helper()
	b := bus.New(16, 256)
	core := New(b, ModuleURLs{})
	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	aegisv1.RegisterAegisCoreServer(grpcServer, core)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return aegisv1.NewAegisCoreClient(conn), func() {
		conn.Close()
		grpcServer.Stop()
		lis.Close()
	}
}

func mkEvent() *aegisv1.ThreatEvent {
	return &aegisv1.ThreatEvent{
		EventId: "test-1",
		Ts:      timestamppb.Now(),
		Source:  aegisv1.EventSource_EVENT_SOURCE_KERNELSHIELD,
		Type:    aegisv1.EventType_EVENT_TYPE_EXECVE,
		Severity: aegisv1.Severity_SEVERITY_HIGH,
		HostId:  "host-1",
		Comm:    "bash",
		Context: map[string]string{"argv": "ls -la"},
	}
}

func TestPublishAck(t *testing.T) {
	client, done := newTestServer(t)
	defer done()

	stream, err := client.Publish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := stream.Send(mkEvent()); err != nil {
			t.Fatal(err)
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	if ack.Accepted != 5 {
		t.Fatalf("expected 5 accepted, got %d", ack.Accepted)
	}
}

func TestStreamEvents(t *testing.T) {
	client, done := newTestServer(t)
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stream, err := client.StreamEvents(ctx, &aegisv1.StreamFilter{
		MinSeverity: aegisv1.Severity_SEVERITY_INFO,
	})
	if err != nil {
		t.Fatal(err)
	}

	// подписка регистрируется асинхронно — публикуем в цикле до получения
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pub, err := client.Publish(ctx)
			if err != nil {
				return
			}
			if err := pub.Send(mkEvent()); err != nil {
				return
			}
			_, _ = pub.CloseAndRecv()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	got, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if got.GetEventId() != "test-1" {
		t.Fatalf("unexpected event: %s", got.GetEventId())
	}
}

func TestBlockIpValidation(t *testing.T) {
	client, done := newTestServer(t)
	defer done()

	_, err := client.BlockIp(context.Background(), &aegisv1.BlockIpRequest{Ip: "not-an-ip"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}

	resp, err := client.BlockIp(context.Background(), &aegisv1.BlockIpRequest{Ip: "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetOk() {
		t.Fatal("expected ok=true")
	}
}

func TestAirGap(t *testing.T) {
	client, done := newTestServer(t)
	defer done()

	resp, err := client.AirGap(context.Background(), &aegisv1.AirGapRequest{Engage: true, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetEngaged() {
		t.Fatal("expected engaged=true")
	}
}

func TestTriggerFuzzUnavailable(t *testing.T) {
	client, done := newTestServer(t)
	defer done()

	// без адреса PulseFuzz job помечается QUEUED (не ошибка)
	job, err := client.TriggerFuzz(context.Background(), &aegisv1.FuzzRequest{TargetUrl: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	if job.GetStatus() != "QUEUED" {
		t.Fatalf("expected QUEUED, got %s", job.GetStatus())
	}
}
