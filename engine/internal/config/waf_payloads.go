package config

// WAFPayloadMode controls payload adaptation independently of request headers.
// The empty value is auto so older stored/API configurations gain the default
// without silently enabling IP spoofing or protocol/header mutations.
type WAFPayloadMode string

const (
	WAFPayloadAuto WAFPayloadMode = "auto"
	WAFPayloadOn   WAFPayloadMode = "on"
	WAFPayloadOff  WAFPayloadMode = "off"
)

func (c ScanConfig) EffectiveWAFPayloadMode() WAFPayloadMode {
	if c.PassiveMode {
		return WAFPayloadOff
	}
	if c.WAFPayloadMode == "" {
		return WAFPayloadAuto
	}
	return c.WAFPayloadMode
}

func (c ScanConfig) WAFPayloadsEnabled() bool {
	mode := c.EffectiveWAFPayloadMode()
	return mode == WAFPayloadAuto || mode == WAFPayloadOn
}
