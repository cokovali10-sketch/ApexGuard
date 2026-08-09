// PulseFuzz — оркестратор: OpenAPI parse → coverage-guided fuzz → JWT forge → IDOR.
// Run: go run ./pulsefuzz -spec api/openapi.json -target http://127.0.0.1:8080
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"apexguard/pulsefuzz/internal/api"
	"apexguard/pulsefuzz/internal/auth"
	"apexguard/pulsefuzz/internal/coverage"
	"apexguard/pulsefuzz/internal/engine"
	"apexguard/pulsefuzz/internal/idor"
	"apexguard/pulsefuzz/internal/mutator"
	"apexguard/pulsefuzz/internal/spec"
)

func main() {
	specPath := flag.String("spec", "api/openapi.json", "path to OpenAPI v3 / GraphQL schema")
	target := flag.String("target", "http://127.0.0.1:8080", "target base URL")
	concurrency := flag.Uint("concurrency", 50, "max concurrent requests")
	iterations := flag.Uint("iterations", 5000, "max total fuzz iterations")
	tokenA := flag.String("token-a", "", "session token user A (IDOR owner)")
	tokenB := flag.String("token-b", "", "session token user B (IDOR intruder)")
	rsaPubKey := flag.String("rsa-pubkey", "", "path to RSA public key PEM (JWT key confusion)")
	jwtSecret := flag.String("jwt-secret", "", "known JWT HMAC secret (if any)")
	listen := flag.String("listen", "", "enable HTTP API server on this addr (e.g. :9091)")
	flag.Parse()

	// HTTP API-сервер (интеграция с ApexCore) — если задан -listen.
	if *listen != "" {
		go func() {
			srv := api.New()
			log.Printf("[pulsefuzz] API listening on %s", *listen)
			if err := http.ListenAndServe(*listen, srv.Handler()); err != nil {
				log.Fatalf("api server: %v", err)
			}
		}()
	}

	if *specPath == "" || !fileExists(*specPath) {
		log.Printf("[pulsefuzz] spec %q not found — skip fuzzing (API server only)", *specPath)
		if *listen == "" {
			log.Fatalf("nothing to do: neither spec nor -listen")
		}
		select {}
	}

	ops, err := spec.ParseOpenAPI(*specPath)
	if err != nil {
		log.Fatalf("parse spec: %v", err)
	}
	fmt.Printf("[pulsefuzz] loaded %d operations from %s\n", len(ops), *specPath)

	client := &http.Client{Timeout: 15 * time.Second}
	m := mutator.New(
		mutator.ModeBoundary|mutator.ModeSQLi|mutator.ModeSSTI|
			mutator.ModeIDOR|mutator.ModeTypeConfusion|mutator.ModeChaos,
		time.Now().UnixNano(),
	)
	corpus := coverage.NewCorpus()
	eng := engine.New(client, *target, corpus, m, int(*concurrency))

	// ---------------- 1. Coverage-guided fuzzing ----------------
	iter := 0
	for _, op := range ops {
		if iter >= int(*iterations) {
			break
		}
		n := eng.FuzzOperation(op.Method, op.Path, op.ExampleBody, op.Params)
		iter += n
	}
	fmt.Printf("[fuzz] done: %d requests, %d anomalies, corpus=%d\n",
		eng.Iterations(), len(eng.Anomalies()), len(corpus.InterestingSeeds()))

	for _, a := range eng.Anomalies() {
		fmt.Printf("  [ANOMALY] %-24s %3d %10v %s %s\n", a.Rule, a.Status, a.Latency, a.Method, a.Payload)
	}

	// ---------------- 2. JWT forgery ----------------
	if *jwtSecret != "" || *rsaPubKey != "" || *tokenA != "" {
		jwtProbes(client, *target, ops, *jwtSecret, *rsaPubKey)
	}

	// ---------------- 3. IDOR cross-session ----------------
	if *tokenA != "" && *tokenB != "" {
		idorCrossCheck(client, *target, *tokenA, *tokenB, ops)
	}
}

// jwtProbes: генерация фальшивых токенов и проверка приёма сервером.
func jwtProbes(c *http.Client, base string, ops []spec.Operation, secret, rsaKey string) {
	// Базовый токен — возьмём из первого параметра/пейлоада, иначе сгенерируем.
	baseToken := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwidWlkIjoiMSJ9." + "AAAA"
	if parsed, err := auth.ParseJWT(baseToken); err == nil {
		probe := func(label, token string) {
			for _, op := range ops {
				if op.Method != "GET" && op.Method != "POST" {
					continue
				}
				code := tryToken(c, base+op.Path, token)
				if code != 401 && code != 403 && code != 0 {
					fmt.Printf("  [JWT][%s] accepted: %s → %d\n", label, op.Path, code)
				}
			}
		}

		// alg=none
		noneToken := parsed.ForgeNone(auth.AdminClaims("1337"))
		probe("alg-none", noneToken)

		// key confusion (RSA pub → HS256)
		if rsaKey != "" {
			pemBytes, err := os.ReadFile(rsaKey)
			if err == nil {
				if kc, err := parsed.ForgeKeyConfusion(pemBytes, auth.AdminClaims("1337")); err == nil {
					probe("key-confusion", kc)
				}
			}
		}
		// известный секрет
		if secret != "" {
			probe("known-secret", parsed.ForgeWithSecret([]byte(secret), auth.AdminClaims("1337")))
		}
	}
}

func tryToken(c *http.Client, url, token string) int {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// idorCrossCheck: два пользователя, перекрёстный доступ к объектам.
func idorCrossCheck(c *http.Client, base, tokenA, tokenB string, ops []spec.Operation) {
	owner := &idor.Session{Name: "user-A", Token: tokenA, Client: c, Base: base}
	intruder := &idor.Session{Name: "user-B", Token: tokenB, Client: c, Base: base}

	// Собираем probe-пути из спецификации (параметры id → пути с placeholder).
	var probePaths []string
	for _, op := range ops {
		if _, hasID := op.Params["id"]; hasID {
			probePaths = append(probePaths, op.Path)
		}
		if _, hasID := op.Params["user_id"]; hasID {
			probePaths = append(probePaths, op.Path)
		}
	}

	// Демо-паттерны, если спецификация не даёт подсказок.
	if len(probePaths) == 0 {
		probePaths = []string{"/api/users/{id}", "/api/orders/{id}", "/api/account/{id}"}
	}

	det := idor.NewDetector()
	// Прогон: владелец собирает ID из своих ответов.
	for _, path := range probePaths {
		body := getBody(c, base+path)
		ids := idor.CollectIDs(body)
		if len(ids) == 0 {
			continue
		}
		det.CrossCheck(owner, intruder, ids, probePaths)
	}

	findings := det.Findings()
	fmt.Printf("[idor] %d finding(s)\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  [IDOR] %s object=%s owner=%s intruder=%s status=%d evidence=%s\n",
			f.URL, f.ObjectID, f.OwnerSession, f.Intruder, f.Status, f.Evidence)
	}
}

func getBody(c *http.Client, url string) []byte {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	return readAll(resp)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readAll(r *http.Response) []byte {
	defer r.Body.Close()
	b := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		b = append(b, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return b
}
