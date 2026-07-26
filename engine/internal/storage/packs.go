package storage

import (
	"database/sql"
	"fmt"
)

type PackArtifact struct {
	PackType      string
	Channel       string
	Version       string
	ManifestJSON  string
	Payload       string
	PayloadSHA256 string
	Active        bool
	InstalledAt   string
}

func (db *DB) SavePackArtifact(artifact PackArtifact) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE pack_artifacts SET active = 0 WHERE pack_type = ? AND channel = ?`,
		artifact.PackType, artifact.Channel); err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO pack_artifacts
  (pack_type, channel, version, manifest_json, payload, payload_sha256, active)
VALUES (?, ?, ?, ?, ?, ?, 1)
ON CONFLICT(pack_type, channel, version) DO UPDATE SET
  manifest_json=excluded.manifest_json,
  payload=excluded.payload,
  payload_sha256=excluded.payload_sha256,
  active=1,
  installed_at=datetime('now')`,
		artifact.PackType, artifact.Channel, artifact.Version, artifact.ManifestJSON,
		artifact.Payload, artifact.PayloadSHA256); err != nil {
		return err
	}
	table, err := packHistoryTable(artifact.PackType)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(
		`INSERT INTO %s (channel, version, metadata_json) VALUES (?, ?, ?)`, table),
		artifact.Channel, artifact.Version, artifact.ManifestJSON); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) ActivatePackArtifact(packType, channel, version string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var manifest string
	if err := tx.QueryRow(`
SELECT manifest_json FROM pack_artifacts
WHERE pack_type = ? AND channel = ? AND version = ?`,
		packType, channel, version).Scan(&manifest); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("pack artifact %s/%s@%s is not installed", packType, channel, version)
		}
		return err
	}
	if _, err := tx.Exec(`UPDATE pack_artifacts SET active = 0 WHERE pack_type = ? AND channel = ?`,
		packType, channel); err != nil {
		return err
	}
	if _, err := tx.Exec(`
UPDATE pack_artifacts SET active = 1
WHERE pack_type = ? AND channel = ? AND version = ?`, packType, channel, version); err != nil {
		return err
	}
	table, err := packHistoryTable(packType)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(
		`INSERT INTO %s (channel, version, metadata_json) VALUES (?, ?, ?)`, table),
		channel, version, manifest); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) ActivePackArtifact(packType, channel string) (PackArtifact, error) {
	var artifact PackArtifact
	var active int
	err := db.conn.QueryRow(`
SELECT pack_type, channel, version, manifest_json, payload, payload_sha256, active, installed_at
FROM pack_artifacts WHERE pack_type = ? AND channel = ? AND active = 1`,
		packType, channel).Scan(&artifact.PackType, &artifact.Channel, &artifact.Version,
		&artifact.ManifestJSON, &artifact.Payload, &artifact.PayloadSHA256, &active, &artifact.InstalledAt)
	artifact.Active = active == 1
	return artifact, err
}

func packHistoryTable(packType string) (string, error) {
	switch packType {
	case "rule":
		return "rule_pack_versions", nil
	case "payload":
		return "payload_pack_versions", nil
	default:
		return "", fmt.Errorf("invalid pack type %q", packType)
	}
}
