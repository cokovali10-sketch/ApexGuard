// ApexCore — центральная шина AegisGuard (gRPC + gRPC-Gateway + WebSocket + /metrics).
//
// Окружение:
//   LISTEN_GRPC    порт gRPC (по умолч. 50051)
//   LISTEN_HTTP    порт HTTP (gateway + ws + metrics, по умолч. 8080)
//   TLS_CERT/TLS_KEY — mTLS сертификаты (SPIFFE/SPIRE); если пусто — plaintext
//   PULSEFUZZ_URL/SHADOWNET_URL/HEXEYE_URL — адреса модулей
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gen "github.com/apexguard/apexguard/core/gen"
	"github.com/apexguard/apexguard/core/internal/bus"
	"github.com/apexguard/apexguard/core/internal/server"
	"github.com/apexguard/apexguard/core/internal/ws"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	log.Info().Msg("apexcore starting")

	grpcAddr := envOr("LISTEN_GRPC", ":50051")
	httpAddr := envOr("LISTEN_HTTP", ":8080")

	b := bus.New(1024, 10_000)
	mods := server.ModuleURLs{
		PulseFuzz: envOr("PULSEFUZZ_URL", ""),
		ShadowNet: envOr("SHADOWNET_URL", ""),
		HexEye:    envOr("HEXEYE_URL", ""),
	}
	coreServer := server.New(b, mods)

	// ---------------- Prometheus ----------------
	evCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "apexcore_events_total", Help: "события через шину",
	}, []string{"source"})
	dropCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "apexcore_drops_total", Help: "drop при переполнении каналов",
	})
	subGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "apexcore_subscribers", Help: "активные WS/gRPC подписчики",
	})
	airgapGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "apexcore_airgap", Help: "Panic Mode (1 = изоляция включена)",
	})
	reg := prometheus.NewRegistry()
	reg.MustRegister(evCounter, dropCounter, subGauge, airgapGauge)

	// метрики-плуг в шину
	metrics := &ws.Metrics{}
	go func() {
		prevEvents, prevDrops := uint64(0), uint64(0)
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for range tick.C {
			events, drops := b.Stats()
			dEvents := events - prevEvents
			dDrops := drops - prevDrops
			prevEvents, prevDrops = events, drops
			metrics.Eps = float64(dEvents) / 2 // событий/сек
			metrics.LatencyMs = 0              // заполняется агентами (RTT)
			evCounter.WithLabelValues("all").Add(float64(dEvents))
			dropCounter.Add(float64(dDrops))
			subGauge.Set(float64(b.SubscriberCount()))
			engaged, _ := b.AirGapState()
			if engaged {
				airgapGauge.Set(1)
			} else {
				airgapGauge.Set(0)
			}
		}
	}()

	// ---------------- gRPC ----------------
	opts := []grpc.ServerOption{}
	creds, err := loadTLSCreds()
	if err != nil {
		log.Warn().Err(err).Msg("TLS disabled (SPIFFE не настроен)")
	} else {
		opts = append(opts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(opts...)
	gen.RegisterAegisCoreServer(grpcServer, coreServer)
	reflection.Register(grpcServer)

	go func() {
		log.Info().Str("addr", grpcAddr).Msg("gRPC listening")
		lis, err := netListen(grpcAddr)
		if err != nil {
			log.Fatal().Err(err).Msg("gRPC listen")
		}
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("gRPC serve")
		}
	}()

	// ---------------- HTTP: gateway + ws + metrics ----------------
	gwMux := runtime.NewServeMux()
	if err := gen.RegisterAegisCoreHandlerServer(context.Background(), gwMux, coreServer); err != nil {
		log.Fatal().Err(err).Msg("register gateway")
	}
	httpMux := http.NewServeMux()
	httpMux.Handle("/v1/", gwMux)
	httpMux.Handle("/ws/events", ws.Handler(b, metrics, 256))
	httpMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	var handler http.Handler = httpMux
	if token := os.Getenv("AUTH_TOKEN"); token != "" {
		log.Info().Msg("AUTH_TOKEN set — console API protected")
		handler = authMiddleware(httpMux, token)
	}

	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info().Str("addr", httpAddr).Msg("HTTP (gateway/ws/metrics) listening")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP serve")
		}
	}()

	// ---------------- graceful shutdown ----------------
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
	grpcServer.GracefulStop()
}

// loadTLSCreds — mTLS из файлов (SPIFFE X509-SVID: certs.pem/key.pem/bundle.pem).
func loadTLSCreds() (credentials.TransportCredentials, error) {
	certFile := envOr("TLS_CERT", "")
	keyFile := envOr("TLS_KEY", "")
	caFile := envOr("TLS_CA", "")
	if certFile == "" || keyFile == "" {
		return nil, os.ErrNotExist
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if caFile != "" {
		pool := x509.NewCertPool()
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, os.ErrInvalid
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert // mutual TLS
	}
	return credentials.NewTLS(cfg), nil
}

func netListen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// authMiddleware требует Bearer-токен на /v1/* и /ws/* (опционально).
func authMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") && !strings.HasPrefix(r.URL.Path, "/ws/") {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
