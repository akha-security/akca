package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const sqliteWriteRetryWindow = 30 * time.Second

// execWriteContext gives short-lived cross-process/UI SQLite locks time to
// clear. Retries are bounded and context-aware; permanent locks still fail
// closed instead of hanging the scan forever.
func (db *DB) execWriteContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	retryCtx, cancel := context.WithTimeout(ctx, sqliteWriteRetryWindow)
	defer cancel()

	delay := 25 * time.Millisecond
	attempts := 0
	for {
		attempts++
		result, err := db.conn.ExecContext(retryCtx, query, args...)
		if err == nil {
			return result, nil
		}
		if !isSQLiteBusy(err) {
			return nil, err
		}
		if retryCtx.Err() != nil {
			return nil, retryCtx.Err()
		}

		timer := time.NewTimer(delay)
		select {
		case <-retryCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, retryCtx.Err()
		case <-timer.C:
		}
		if delay < 500*time.Millisecond {
			delay *= 2
			if delay > 500*time.Millisecond {
				delay = 500 * time.Millisecond
			}
		}
		if attempts >= 128 {
			return nil, fmt.Errorf("sqlite write remained busy after %d attempts: %w", attempts, err)
		}
	}
}

func (db *DB) execWrite(query string, args ...interface{}) (sql.Result, error) {
	return db.execWriteContext(context.Background(), query, args...)
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "sqlite_locked") ||
		strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked")
}
