package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// GenerateScanID returns a filesystem- and database-safe identifier for a new
// scan. The target hash makes IDs recognizable, while nanosecond time and
// cryptographic randomness keep simultaneous processes from colliding.
func GenerateScanID(targets []string) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		fallback := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())))
		copy(random, fallback[:len(random)])
	}
	targetPrefix := ""
	if len(targets) > 0 {
		sorted := append([]string(nil), targets...)
		sort.Strings(sorted)
		hash := sha256.Sum256([]byte(strings.Join(sorted, "|")))
		targetPrefix = hex.EncodeToString(hash[:4]) + "-"
	}
	return fmt.Sprintf("scan-%s%d-%s", targetPrefix, time.Now().UnixNano(), hex.EncodeToString(random))
}
