package packs

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/rulesdk"
	"github.com/akha-security/akca/engine/internal/storage"
)

type Manager struct {
	db          *storage.DB
	trustedKeys map[string]ed25519.PublicKey
}

func NewManager(db *storage.DB) *Manager {
	return &Manager{db: db, trustedKeys: make(map[string]ed25519.PublicKey)}
}

type Manifest struct {
	PackType          string `json:"pack_type"`
	Channel           string `json:"channel"`
	Version           string `json:"version"`
	Compatibility     string `json:"compatibility_version,omitempty"`
	PayloadSHA256     string `json:"payload_sha256"`
	KeyID             string `json:"key_id,omitempty"`
	Signature         string `json:"signature,omitempty"`
	SignatureVerified bool   `json:"signature_verified"`
	Source            string `json:"source"`
	Changelog         string `json:"changelog"`
	Compatible        bool   `json:"compatible"`
}

func (m *Manager) Current(packType string) ([]storage.PackVersion, error) {
	return m.db.ListPackVersions(packType)
}

// Install is the explicit local/offline install path. It records a checksum,
// but deliberately does not claim that the package was publisher-signed.
func (m *Manager) Install(packType, channel, version, payload string) (Manifest, error) {
	if packType != "rule" && packType != "payload" {
		return Manifest{}, fmt.Errorf("invalid pack type %q", packType)
	}
	if strings.TrimSpace(channel) == "" || !rulesdk.IsSemanticVersion(version) {
		return Manifest{}, fmt.Errorf("pack channel and semantic version are required")
	}
	if _, err := rulesdk.Parse([]byte(payload)); err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		PackType: packType, Channel: channel, Version: version, PayloadSHA256: payloadDigest(payload),
		Compatibility: rulesdk.Version, Source: "local", Changelog: "Installed " + version, Compatible: true,
	}
	if err := m.persist(manifest, payload); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// TrustKey installs a publisher public key for the lifetime of the manager.
// The caller is responsible for loading this key from a trusted local/admin
// configuration, never from the same untrusted update response as the pack.
func (m *Manager) TrustKey(keyID, encodedPublicKey string) error {
	keyID = strings.TrimSpace(keyID)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPublicKey))
	if err != nil || len(raw) != ed25519.PublicKeySize || keyID == "" {
		return fmt.Errorf("invalid Ed25519 publisher key")
	}
	m.trustedKeys[keyID] = append(ed25519.PublicKey(nil), raw...)
	return nil
}

// InstallSigned verifies publisher provenance and payload integrity before
// changing the active version history.
func (m *Manager) InstallSigned(manifest Manifest, payload, engineCompatibility string) (Manifest, error) {
	key, trusted := m.trustedKeys[strings.TrimSpace(manifest.KeyID)]
	if !trusted {
		return Manifest{}, fmt.Errorf("untrusted pack signing key %q", manifest.KeyID)
	}
	if manifest.PackType != "rule" && manifest.PackType != "payload" {
		return Manifest{}, fmt.Errorf("invalid pack type %q", manifest.PackType)
	}
	if strings.TrimSpace(manifest.Channel) == "" || strings.TrimSpace(manifest.Version) == "" ||
		strings.TrimSpace(manifest.Compatibility) == "" {
		return Manifest{}, fmt.Errorf("signed pack manifest is incomplete")
	}
	if !rulesdk.IsSemanticVersion(manifest.Version) || !rulesdk.IsSemanticVersion(manifest.Compatibility) {
		return Manifest{}, fmt.Errorf("signed pack manifest requires semantic versions")
	}
	actualDigest := payloadDigest(payload)
	if !strings.EqualFold(actualDigest, strings.TrimSpace(manifest.PayloadSHA256)) {
		return Manifest{}, fmt.Errorf("pack payload checksum mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(manifest.Signature))
	if err != nil || !ed25519.Verify(key, manifestSigningBytes(manifest), signature) {
		return Manifest{}, fmt.Errorf("pack signature verification failed")
	}
	if !m.CheckCompatibility(engineCompatibility, manifest.Compatibility) {
		return Manifest{}, fmt.Errorf("pack compatibility %q is not supported by engine %q",
			manifest.Compatibility, engineCompatibility)
	}
	if _, err := rulesdk.Parse([]byte(payload)); err != nil {
		return Manifest{}, err
	}
	manifest.PayloadSHA256 = actualDigest
	manifest.SignatureVerified = true
	manifest.Source = "signed_update"
	manifest.Compatible = true
	if err := m.persist(manifest, payload); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m *Manager) persist(manifest Manifest, payload string) error {
	if m.db == nil {
		return fmt.Errorf("pack storage is unavailable")
	}
	meta, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return m.db.SavePackArtifact(storage.PackArtifact{
		PackType: manifest.PackType, Channel: manifest.Channel, Version: manifest.Version,
		ManifestJSON: string(meta), Payload: payload, PayloadSHA256: manifest.PayloadSHA256, Active: true,
	})
}

func (m *Manager) Rollback(packType, channel, version string) error {
	if m.db == nil {
		return fmt.Errorf("pack storage is unavailable")
	}
	return m.db.ActivatePackArtifact(packType, channel, version)
}

// LoadActive returns the exact previously verified artifact. It performs all
// integrity and compatibility checks again so offline startup cannot silently
// accept a corrupted database row.
func (m *Manager) LoadActive(packType, channel, engineCompatibility string) (Manifest, string, error) {
	if m.db == nil {
		return Manifest{}, "", fmt.Errorf("pack storage is unavailable")
	}
	artifact, err := m.db.ActivePackArtifact(packType, channel)
	if err != nil {
		return Manifest{}, "", err
	}
	var manifest Manifest
	if err := json.Unmarshal([]byte(artifact.ManifestJSON), &manifest); err != nil {
		return Manifest{}, "", fmt.Errorf("stored pack manifest is invalid: %w", err)
	}
	if payloadDigest(artifact.Payload) != strings.ToLower(artifact.PayloadSHA256) ||
		!strings.EqualFold(artifact.PayloadSHA256, manifest.PayloadSHA256) {
		return Manifest{}, "", fmt.Errorf("stored pack artifact checksum mismatch")
	}
	if !m.CheckCompatibility(engineCompatibility, manifest.Compatibility) {
		return Manifest{}, "", fmt.Errorf("stored pack is incompatible with engine %q", engineCompatibility)
	}
	if _, err := rulesdk.Parse([]byte(artifact.Payload)); err != nil {
		return Manifest{}, "", err
	}
	return manifest, artifact.Payload, nil
}

func (m *Manager) CheckCompatibility(engineVersion, packVersion string) bool {
	engineMajor := majorVersion(engineVersion)
	packMajor := majorVersion(packVersion)
	return engineMajor == "" || packMajor != "" && engineMajor == packMajor
}

func payloadDigest(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func manifestSigningBytes(manifest Manifest) []byte {
	return []byte(strings.Join([]string{
		manifest.PackType, manifest.Channel, manifest.Version, manifest.Compatibility,
		strings.ToLower(manifest.PayloadSHA256),
	}, "\n"))
}

func majorVersion(version string) string {
	version = strings.TrimSpace(strings.TrimPrefix(version, "v"))
	if version == "" {
		return ""
	}
	if index := strings.IndexByte(version, '.'); index >= 0 {
		version = version[:index]
	}
	for _, r := range version {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return version
}

func FormatManifest(m Manifest) string {
	signature := "unverified"
	if m.SignatureVerified && len(m.Signature) >= 8 {
		signature = m.Signature[:8]
	}
	return fmt.Sprintf("%s@%s sig=%s compatible=%v", m.Channel, m.Version, signature, m.Compatible)
}
