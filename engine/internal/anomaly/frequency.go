package anomaly

import (
	"sync"
)

type ValueCounter struct {
	valueCounts map[uint32]int
	mu          sync.RWMutex
}

func newValueCounter() *ValueCounter {
	return &ValueCounter{
		valueCounts: make(map[uint32]int),
	}
}

func (vc *ValueCounter) incrementAndCheckNovel(value uint32) bool {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	currentCount := vc.valueCounts[value]
	vc.valueCounts[value] = currentCount + 1
	return currentCount == 0
}

func (vc *ValueCounter) getCount(value uint32) int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.valueCounts[value]
}

func (vc *ValueCounter) isVariant() bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.valueCounts) > 1
}

type AttributeFrequencyTracker struct {
	counters map[Type]*ValueCounter
	mu       sync.RWMutex
}

func NewAttributeFrequencyTracker() *AttributeFrequencyTracker {
	return &AttributeFrequencyTracker{
		counters: make(map[Type]*ValueCounter),
	}
}

func (aft *AttributeFrequencyTracker) RecordValue(attrType Type, value uint32) bool {
	aft.mu.Lock()
	counter, exists := aft.counters[attrType]
	if !exists {
		counter = newValueCounter()
		aft.counters[attrType] = counter
	}
	aft.mu.Unlock()

	return counter.incrementAndCheckNovel(value)
}

func (aft *AttributeFrequencyTracker) GetFrequency(attrType Type, value uint32) int {
	aft.mu.RLock()
	counter, exists := aft.counters[attrType]
	aft.mu.RUnlock()

	if !exists {
		return 0
	}
	return counter.getCount(value)
}

func (aft *AttributeFrequencyTracker) GetVariantAttributes() []Type {
	aft.mu.RLock()
	defer aft.mu.RUnlock()

	var variants []Type
	for attrType, counter := range aft.counters {
		if counter.isVariant() {
			variants = append(variants, attrType)
		}
	}
	return variants
}
