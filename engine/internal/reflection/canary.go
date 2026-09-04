package reflection

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const canaryPrefix = "akca"

func NewCanary() (id, value string) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		nano := time.Now().UnixNano()
		b[0] = byte(nano)
		b[1] = byte(nano >> 8)
		b[2] = byte(nano >> 16)
		b[3] = byte(nano >> 24)
	}
	id = hex.EncodeToString(b)
	value = fmt.Sprintf("%s%s9z", canaryPrefix, id)
	return id, value
}

func IsCanaryMarker(s string) bool {
	// canary is "akca" (4) + 8 hex chars + "9z" (2) = 14 chars
	return len(s) == 14 && s[:len(canaryPrefix)] == canaryPrefix && s[12:] == "9z"
}
