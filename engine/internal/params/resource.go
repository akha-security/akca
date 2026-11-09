package params

import (
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/targeting"
)

func (d *Discoverer) SetForcedActiveURLs(urls []string) { d.forceURLs = append([]string(nil), urls...) }

func discoverableResource(raw, method string, template storage.DiscoveryRequestTemplate) bool {
	return targeting.InactiveReason(targeting.Resource{URL: raw, Method: method, Status: template.ResponseStatus,
		ContentType: headerValue(template.ResponseHeaders, "Content-Type"), Body: template.ResponseBody,
		DynamicInput: template.Body != ""}) == ""
}
