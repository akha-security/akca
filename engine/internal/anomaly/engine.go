package anomaly

import (
	"fmt"
	"sort"
)

type Engine struct {
	attributeTypes []Type
}

func NewEngine(attributeTypes []Type) *Engine {
	if len(attributeTypes) == 0 {
		attributeTypes = AllFingerprintAttributes
	}
	return &Engine{
		attributeTypes: attributeTypes,
	}
}

func NewDefaultEngine() *Engine {
	return NewEngine(nil)
}

// Rank analyzes a collection of ResponseRecords and computes their Anomaly Score.
func (e *Engine) Rank(records []*ResponseRecord) error {
	if len(records) == 0 {
		return nil
	}

	frequencyTracker := NewAttributeFrequencyTracker()
	weightManager := NewAttributeWeightManager(e.attributeTypes)

	for _, record := range records {
		for _, attrType := range e.attributeTypes {
			value, ok := record.Attributes.Get(attrType)
			if !ok || value == 0 {
				continue
			}

			isNovel := frequencyTracker.RecordValue(attrType, value)
			if isNovel {
				weightManager.DegradeWeight(attrType)
			}
		}
	}

	variantAttributes := frequencyTracker.GetVariantAttributes()
	if len(variantAttributes) == 0 {
		for _, record := range records {
			record.Score = 0
		}
		return nil
	}

	calculator := NewAnomalyScoreCalculator(
		frequencyTracker,
		weightManager,
		variantAttributes,
	)

	for _, record := range records {
		score, err := calculator.CalculateScore(&record.Attributes)
		if err != nil {
			return fmt.Errorf("failed to calculate score: %w", err)
		}
		record.Score = score
	}

	return nil
}

// RankAndSort ranks records and sorts them descending by Anomaly Score (most anomalous first).
func (e *Engine) RankAndSort(records []*ResponseRecord) error {
	if err := e.Rank(records); err != nil {
		return err
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Score > records[j].Score
	})
	return nil
}
