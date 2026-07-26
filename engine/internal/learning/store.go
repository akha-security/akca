package learning

import (
	"github.com/akha-security/akca/engine/internal/storage"
)

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
	return Merge(p, ep)
}

func profileFromData(domain, endpointURL string, raw storage.LearningProfileData) Profile {
	return Profile{
		Domain: domain, EndpointURL: endpointURL,
		Worked: raw.Worked, Blocked: raw.Blocked, Noisy: raw.Noisy, FalsePositive: raw.FalsePositive,
		Stability: map[string]int{}, WAFBlocks: map[string]int{},
	}
}

func (s *Store) Save(p Profile) error {
	if s.db == nil {
		return nil
	}
	data := storage.LearningProfileData{
		Worked: p.Worked, Blocked: p.Blocked, Noisy: p.Noisy, FalsePositive: p.FalsePositive,
	}
	return s.db.SaveLearningProfile(p.Domain, p.EndpointURL, data)
}

func (s *Store) RecordOutcome(domain, endpointURL, family string, outcome Outcome) error {
	p := s.Load(domain, endpointURL)
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
