package learning

import (
	"github.com/akha-security/akca/engine/internal/storage"
	"sync"
)

var outcomeWriteMu sync.Mutex

type Store struct {
	db *storage.DB
}

func NewStore(db *storage.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Load(domain, endpointURL string) Profile {
	if s.db == nil {
		return NewProfile(domain, endpointURL)
	}
	domainRaw, _ := s.db.LoadLearningProfile(domain, "")
	p := profileFromData(domain, "", domainRaw)
	if endpointURL == "" {
		return p
	}
	epRaw, _ := s.db.LoadLearningProfile(domain, endpointURL)
	ep := profileFromData(domain, endpointURL, epRaw)
	merged := Merge(p, ep)
	// Domain statistics already contain these endpoint events. Use endpoint counts
	// when available instead of adding the same events a second time.
	if len(ep.OutcomeCounts) > 0 {
		merged.OutcomeCounts = cloneOutcomeCounts(ep.OutcomeCounts)
	}
	return merged
}

func profileFromData(domain, endpointURL string, raw storage.LearningProfileData) Profile {
	return Profile{
		Domain: domain, EndpointURL: endpointURL,
		Worked: raw.Worked, Blocked: raw.Blocked, Noisy: raw.Noisy, FalsePositive: raw.FalsePositive,
		Stability: raw.Stability, WAFBlocks: raw.WAFBlocks, OutcomeCounts: raw.OutcomeCounts,
	}
}

func (s *Store) Save(p Profile) error {
	if s.db == nil {
		return nil
	}
	data := storage.LearningProfileData{
		Worked: p.Worked, Blocked: p.Blocked, Noisy: p.Noisy, FalsePositive: p.FalsePositive,
		OutcomeCounts: p.OutcomeCounts, Stability: p.Stability, WAFBlocks: p.WAFBlocks,
	}
	return s.db.SaveLearningProfile(p.Domain, p.EndpointURL, data)
}

func (s *Store) RecordOutcome(domain, endpointURL, family string, outcome Outcome) error {
	if s.db == nil {
		return nil
	}
	outcomeWriteMu.Lock()
	defer outcomeWriteMu.Unlock()
	raw, err := s.db.LoadLearningProfile(domain, endpointURL)
	if err != nil {
		return err
	}
	p := profileFromData(domain, endpointURL, raw)
	p.Domain = domain
	p.EndpointURL = endpointURL
	p = p.Record(family, outcome)
	return s.Save(p)
}

func (s *Store) Export(domain, endpointURL string) ([]byte, error) {
	return s.Load(domain, endpointURL).ExportJSON()
}

func (s *Store) Import(raw []byte) error {
	p, err := ImportJSON(raw)
	if err != nil {
		return err
	}
	return s.Save(p)
}

func (s *Store) ListDomains() ([]string, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.ListLearningDomains()
}
