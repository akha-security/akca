package evidencestore

import (
	"encoding/json"

	"github.com/akha-security/akca/engine/internal/storage"
)

type Store struct {
	db *storage.DB
}

func New(db *storage.DB) *Store {
	return &Store{db: db}
}

type ScanBundle struct {
	ScanID            string                                  `json:"scan_id"`
	ConfigJSON        string                                  `json:"config_json,omitempty"`
	Findings          []storage.FindingRecord                 `json:"findings"`
	FindingGroups     []storage.FindingGroupRecord            `json:"finding_groups"`
	RootCauseClusters []storage.RootCauseClusterRecord        `json:"root_cause_clusters"`
	Evidence          []storage.EvidenceRecord                `json:"evidence"`
	RequestResponses  []storage.RequestResponseRecord         `json:"request_responses"`
	WAFProfiles       []storage.WAFProfileRecord              `json:"waf_profiles"`
	TechFingerprints  []storage.TechFingerprintRecord         `json:"tech_fingerprints"`
	FuzzResults       []storage.FuzzResultRecord              `json:"fuzz_results"`
	OASTCallbacks     []storage.OASTCallbackRecord            `json:"oast_callbacks"`
	PayloadOutcomes   []storage.PayloadOutcomeRecord          `json:"payload_outcomes"`
	AuthProfiles      []storage.AuthProfileRecord             `json:"auth_profiles"`
	RoleProfiles      []storage.RoleProfileRecord             `json:"role_profiles"`
	Checkpoints       []storage.CheckpointRecord              `json:"checkpoints"`
	ResumeState       []storage.ResumeStateRecord             `json:"resume_state"`
	HealthSnapshots   []storage.HealthSnapshotRecord          `json:"health_snapshots"`
	APIKeyValidations []storage.APIKeyValidationRecord        `json:"api_key_validations"`
	Observations      []storage.VerificationObservationRecord `json:"verification_observations"`
	Partial           bool                                    `json:"partial"`
}

func (s *Store) LoadBundle(scanID string, partial bool, limits storage.EvidenceLimits) (ScanBundle, error) {
	if limits.Findings <= 0 {
		limits = storage.DefaultEvidenceLimits()
	}
	b := ScanBundle{ScanID: scanID, Partial: partial}
	cfg, _ := s.db.GetScanConfig(scanID)
	b.ConfigJSON = cfg

	var err error
	if b.Findings, err = s.db.ListFindings(scanID, limits.Findings, 0); err != nil {
		return b, err
	}
	if b.FindingGroups, err = s.db.ListFindingGroups(scanID, limits.Groups); err != nil {
		return b, err
	}
	if b.RootCauseClusters, err = s.db.ListRootCauseClusters(scanID, limits.Clusters); err != nil {
		return b, err
	}
	if b.Evidence, err = s.db.ListEvidenceRecords(scanID, limits.Evidence); err != nil {
		return b, err
	}
	if b.RequestResponses, err = s.db.ListRequestResponses(scanID, limits.Requests); err != nil {
		return b, err
	}
	if b.WAFProfiles, err = s.db.ListWAFProfileRecords(scanID, limits.Profiles); err != nil {
		return b, err
	}
	if b.TechFingerprints, err = s.db.ListTechFingerprintRecords(scanID, limits.Profiles); err != nil {
		return b, err
	}
	if b.FuzzResults, err = s.db.ListFuzzResultRecords(scanID, limits.Fuzz); err != nil {
		return b, err
	}
	if b.OASTCallbacks, err = s.db.ListOASTCallbackRecords(scanID, limits.OAST); err != nil {
		return b, err
	}
	if b.PayloadOutcomes, err = s.db.ListPayloadOutcomeRecords(scanID, limits.Outcomes); err != nil {
		return b, err
	}
	if b.AuthProfiles, err = s.db.ListAuthProfileRecords(scanID, limits.Profiles); err != nil {
		return b, err
	}
	if b.RoleProfiles, err = s.db.ListRoleProfileRecords(scanID, limits.Profiles); err != nil {
		return b, err
	}
	if b.Checkpoints, err = s.db.ListCheckpointRecords(scanID, limits.Checkpoints); err != nil {
		return b, err
	}
	if b.ResumeState, err = s.db.ListResumeStateRecords(scanID, limits.Checkpoints); err != nil {
		return b, err
	}
	if b.HealthSnapshots, err = s.db.ListHealthSnapshotRecords(scanID, limits.Health); err != nil {
		return b, err
	}
	if b.APIKeyValidations, err = s.db.ListAPIKeyValidationRecords(scanID, limits.APIKeys); err != nil {
		return b, err
	}
	if b.Observations, err = s.db.ListVerificationObservations(scanID, 0, limits.Observations); err != nil {
		return b, err
	}
	return b, nil
}

func (s *Store) IterateFindings(scanID string, fn func(storage.FindingRecord) error) error {
	return s.db.IterateFindings(scanID, fn)
}

func (s *Store) SaveReportRecord(scanID, template, format, path string, doc interface{}) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return s.db.SaveReportRecord(scanID, template, format, path, string(raw))
}
