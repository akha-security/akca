package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratedPayloadWriteRetriesTransientSQLiteBusy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	holder, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := holder.Migrate(); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Conn().Exec(`PRAGMA busy_timeout = 1`); err != nil {
		t.Fatal(err)
	}

	tx, err := holder.Conn().Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO payload_library_items (name, payload_json) VALUES ('lock-holder', '{}')`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- writer.SaveGeneratedPayloadsContext(
			context.Background(), "scan-1", "https://example.test/?id=1", "id",
			map[string]interface{}{"payloads": []string{"test"}},
		)
	}()
	time.Sleep(100 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("transient SQLite lock was not retried: %v", err)
	}
}

func TestGeneratedPayloadWriteStopsWhenContextExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy-cancel.db")
	holder, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := holder.Migrate(); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Conn().Exec(`PRAGMA busy_timeout = 1`); err != nil {
		t.Fatal(err)
	}

	tx, err := holder.Conn().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO payload_library_items (name, payload_json) VALUES ('lock-holder', '{}')`); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	err = writer.SaveGeneratedPayloadsContext(
		ctx, "scan-1", "https://example.test/?id=1", "id",
		map[string]interface{}{"payloads": []string{"test"}},
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline while lock persisted, got %v", err)
	}
}
