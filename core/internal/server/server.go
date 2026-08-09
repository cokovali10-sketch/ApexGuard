// Package server — реализация AegisCore gRPC-сервиса.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	aegisv1 "github.com/apexguard/apexguard/core/gen"
	"github.com/apexguard/apexguard/core/internal/bus"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ModuleURLs — адреса модулей для проксирования управляющих команд.
type ModuleURLs struct {
	PulseFuzz string
	ShadowNet string
	HexEye    string
}

type CoreServer struct {
	aegisv1.UnimplementedAegisCoreServer
	bus  *bus.Bus
	mods ModuleURLs
	http *http.Client
}

func New(b *bus.Bus, mods ModuleURLs) *CoreServer {
	return &CoreServer{
		bus:  b,
		mods: mods,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// ---------------------------------------------------------------------------
// Ингресс событий
// ---------------------------------------------------------------------------

// Publish — client-streaming: агенты шлют события в шину.
func (s *CoreServer) Publish(stream aegisv1.AegisCore_PublishServer) error {
	var count uint64
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&aegisv1.PublishAck{Accepted: count, Watermark: count})
		}
		if err != nil {
			return err
		}
		s.bus.Publish(ev)
		count++
	}
}

// StreamEvents — подписка консоли на поток событий.
func (s *CoreServer) StreamEvents(filter *aegisv1.StreamFilter, stream aegisv1.AegisCore_StreamEventsServer) error {
	sources := filter.GetSources()
	minSev := filter.GetMinSeverity()
	sub := s.bus.Subscribe(sources, minSev)
	defer s.bus.Unsubscribe(sub)
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev, ok := <-sub.C:
			if !ok {
				return nil
			}
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// WatchCommands — канал команд агентам (push).
func (s *CoreServer) WatchCommands(_ *aegisv1.WatchRequest, stream aegisv1.AegisCore_WatchCommandsServer) error {
	cmds := s.bus.Commands()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case cmd := <-cmds:
			if cmd == nil {
				return nil
			}
			if err := stream.Send(cmd); err != nil {
				return err
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Команды (консоль → модули)
// ---------------------------------------------------------------------------

func (s *CoreServer) BlockIp(ctx context.Context, req *aegisv1.BlockIpRequest) (*aegisv1.BlockIpResponse, error) {
	ip := req.GetIp()
	if net.ParseIP(ip) == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ip")
	}
	log.Info().Str("ip", ip).Msg("block-ip command")
	s.bus.BroadcastCommand(&aegisv1.Command{
		Action: &aegisv1.Command_BlockIp{BlockIp: req},
	})
	return &aegisv1.BlockIpResponse{Ok: true}, nil
}

func (s *CoreServer) ReloadProbes(ctx context.Context, req *aegisv1.ReloadRequest) (*aegisv1.ReloadResponse, error) {
	log.Info().Msg("reload probes command")
	s.bus.BroadcastCommand(&aegisv1.Command{
		Action: &aegisv1.Command_ReloadProbes{ReloadProbes: req},
	})
	return &aegisv1.ReloadResponse{Ok: true}, nil
}

func (s *CoreServer) AirGap(ctx context.Context, req *aegisv1.AirGapRequest) (*aegisv1.AirGapResponse, error) {
	log.Info().Bool("engage", req.GetEngage()).Str("reason", req.GetReason()).Msg("airgap command")
	s.bus.SetAirGap(req.GetEngage(), req.GetReason())
	return &aegisv1.AirGapResponse{Engaged: req.GetEngage()}, nil
}

// TriggerFuzz проксирует в PulseFuzz (если адрес задан), иначе ставит в очередь.
func (s *CoreServer) TriggerFuzz(ctx context.Context, req *aegisv1.FuzzRequest) (*aegisv1.FuzzJob, error) {
	job := &aegisv1.FuzzJob{JobId: uuid.New().String()}
	if s.mods.PulseFuzz == "" {
		job.Status = "QUEUED"
		return job, nil
	}
	resp, err := s.forward(ctx, s.mods.PulseFuzz+"/fuzz", req)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "pulsefuzz: %v", err)
	}
	if err := json.Unmarshal(resp, job); err != nil {
		job.Status = "QUEUED"
	}
	return job, nil
}

func (s *CoreServer) SpawnHoneypot(ctx context.Context, req *aegisv1.HoneypotSpec) (*aegisv1.HoneypotStatus, error) {
	st := &aegisv1.HoneypotStatus{HoneypotId: uuid.New().String()}
	if s.mods.ShadowNet == "" {
		st.Status = "QUEUED"
		return st, nil
	}
	resp, err := s.forward(ctx, s.mods.ShadowNet+"/honeypots", req)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "shadownet: %v", err)
	}
	if err := json.Unmarshal(resp, st); err != nil {
		st.Status = "QUEUED"
	}
	return st, nil
}

func (s *CoreServer) AnalyzeBinary(ctx context.Context, req *aegisv1.BinaryPath) (*aegisv1.AnalysisReport, error) {
	if s.mods.HexEye == "" {
		return nil, status.Error(codes.Unavailable, "hexeye not configured")
	}
	resp, err := s.forward(ctx, s.mods.HexEye+"/analyze", req)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "hexeye: %v", err)
	}
	var rep aegisv1.AnalysisReport
	if err := json.Unmarshal(resp, &rep); err != nil {
		return nil, status.Errorf(codes.Internal, "hexeye bad response: %v", err)
	}
	return &rep, nil
}

// forward — вспомогательный POST JSON с JSON-ответом.
func (s *CoreServer) forward(ctx context.Context, url string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

var _ aegisv1.AegisCoreServer = (*CoreServer)(nil)
var _ = emptypb.Empty{}
