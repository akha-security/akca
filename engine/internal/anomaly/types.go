package anomaly

// AttributeSet stores extracted attribute hash values from an HTTP response.
type AttributeSet struct {
	values map[Type]uint32
}

func NewAttributeSet() *AttributeSet {
	return &AttributeSet{
		values: make(map[Type]uint32),
	}
}

func (as *AttributeSet) Set(attrType Type, value uint32) {
	if value != 0 {
		as.values[attrType] = value
	}
}

func (as *AttributeSet) Get(attrType Type) (uint32, bool) {
	value, ok := as.values[attrType]
	return value, ok && value != 0
}

func (as *AttributeSet) GetAll() map[Type]uint32 {
	result := make(map[Type]uint32, len(as.values))
	for k, v := range as.values {
		if v != 0 {
			result[k] = v
		}
	}
	return result
}

// ResponseRecord represents a response with its attributes, user metadata, and anomaly score.
type ResponseRecord struct {
	Attributes AttributeSet
	Metadata   interface{}
	Score      int
}

func NewResponseRecord(attrs AttributeSet, metadata interface{}) *ResponseRecord {
	return &ResponseRecord{
		Attributes: attrs,
		Metadata:   metadata,
		Score:      0,
	}
}
