package auth_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"apexguard/pulsefuzz/internal/auth"
)

func TestJWTForge(t *testing.T) {
	// валидный JWT (учебный)
	tok := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidWlkIjoiMSJ9.SIGNATURE"
	j, err := auth.ParseJWT(tok)
	if err != nil {
		t.Fatal(err)
	}

	// alg=none
	none := j.ForgeNone(auth.AdminClaims("1337"))
	if len(none) == 0 {
		t.Fatal("alg-none empty")
	}

	// известный секрет
	hs := j.ForgeWithSecret([]byte("s3cret"), auth.TargetClaims("999"))
	if len(hs) == 0 {
		t.Fatal("hs256 empty")
	}

	// key confusion
	priv, err := auth.GenerateTestRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	kc, err := j.ForgeKeyConfusion(pemBytes, auth.AdminClaims("1337"))
	if err != nil {
		t.Fatalf("key confusion: %v", err)
	}
	if len(kc) == 0 {
		t.Fatal("key confusion empty")
	}
	t.Logf("alg-none: %s...", none[:20])
	t.Logf("key-confusion: %s...", kc[:20])
}
