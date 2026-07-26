package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

type BaselineFingerprint struct {
	Key        BaselineKey `json:"key"`
	StatusCode int         `json:"status_code"`
	BodyHash   string      `json:"body_hash"`
	BodyLength int         `json:"body_length"`
	HeaderHash string      `json:"header_hash"`
	Host       string      `json:"host"`
}

func FingerprintBaseline(key BaselineKey, snap ResponseSnapshot, host string) BaselineFingerprint {
	return BaselineFingerprint{
		Key: key, StatusCode: snap.StatusCode, BodyLength: len(snap.Body),
		BodyHash: hashBody(snap.Body), HeaderHash: hashHeaders(snap.Headers), Host: host,
	}
}

func CompareParameterBaseline(base, probe ResponseSnapshot) bool {
	if base.StatusCode != probe.StatusCode {
		return false
	}
	if hashBody(NormalizeVolatileFields(base.Body)) != hashBody(NormalizeVolatileFields(probe.Body)) {
		return false
	}
	return true
}

func CompareHostBaseline(hostBase BaselineFingerprint, probe ResponseSnapshot) bool {
	return hostBase.StatusCode == probe.StatusCode && abs(hostBase.BodyLength-len(probe.Body)) <= 32
}

func hashBody(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:8])
}

func hashHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(strings.ToLower(k))
		b.WriteByte(':')
		b.WriteString(headers[k])
		b.WriteByte(';')
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:8])
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
