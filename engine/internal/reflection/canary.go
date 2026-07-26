package reflection

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const canaryPrefix = "akca"

func NewCanary() (id, value string) {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	id = hex.EncodeToString(b)
	value = fmt.Sprintf("%s%s9z", canaryPrefix, id)
	return id, value
}

func IsCanaryMarker(s string) bool {
	return len(s) >= len(canaryPrefix)+5 && s[:len(canaryPrefix)] == canaryPrefix
}
