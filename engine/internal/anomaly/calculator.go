package anomaly

import (
	"fmt"
	"math"
)

const scoreScaleFactor = 10000

type AnomalyScoreCalculator struct {
	frequencyTracker  *AttributeFrequencyTracker
	weightManager     *AttributeWeightManager
	variantAttributes []Type
}

func NewAnomalyScoreCalculator(
	frequencyTracker *AttributeFrequencyTracker,
	weightManager *AttributeWeightManager,
	variantAttributes []Type,
) *AnomalyScoreCalculator {
	return &AnomalyScoreCalculator{
		frequencyTracker:  frequencyTracker,
		weightManager:     weightManager,
		variantAttributes: variantAttributes,
	}
}

func (calc *AnomalyScoreCalculator) CalculateScore(attrs *AttributeSet) (int, error) {
	if attrs == nil {
		return 0, fmt.Errorf("AttributeSet is nil")
	}

	var rawScore float64
	for _, attrType := range calc.variantAttributes {
		value, ok := attrs.Get(attrType)
		if !ok || value == 0 {
			continue
		}

		frequency := calc.frequencyTracker.GetFrequency(attrType, value)
		if frequency == 0 {
			continue
		}

		weight := calc.weightManager.GetWeight(attrType)
		rawScore += weight / float64(frequency)
	}

	scaledScore := rawScore * scoreScaleFactor
	if scaledScore > math.MaxInt32 {
		return 0, fmt.Errorf("score overflow: %.2f", scaledScore)
	}

	return int(math.Round(scaledScore)), nil
}
