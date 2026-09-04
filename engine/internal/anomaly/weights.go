package anomaly

import (
	"sync"
)

const (
	initialWeight     = 1.0
	degradationFactor = 0.9
)

type AttributeWeightManager struct {
	weights map[Type]float64
	mu      sync.RWMutex
}

func NewAttributeWeightManager(attributeTypes []Type) *AttributeWeightManager {
	awm := &AttributeWeightManager{
		weights: make(map[Type]float64, len(attributeTypes)),
	}
	for _, attrType := range attributeTypes {
		awm.weights[attrType] = initialWeight
	}
	return awm
}

func (awm *AttributeWeightManager) DegradeWeight(attrType Type) {
	awm.mu.Lock()
	defer awm.mu.Unlock()

	if currentWeight, exists := awm.weights[attrType]; exists {
		awm.weights[attrType] = currentWeight * degradationFactor
	}
}

func (awm *AttributeWeightManager) GetWeight(attrType Type) float64 {
	awm.mu.RLock()
	defer awm.mu.RUnlock()

	if weight, exists := awm.weights[attrType]; exists {
		return weight
	}
	return initialWeight
}
