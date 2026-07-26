package correlation

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/storage"
)

type Engine struct {
	db *storage.DB
}

func NewEngine(db *storage.DB) *Engine {
	return &Engine{db: db}
}

type Group struct {
	RootCause string   `json:"root_cause"`
	Template  string   `json:"template"`
	Instances []int64  `json:"finding_ids"`
	Titles    []string `json:"titles"`
	Count     int      `json:"count"`
}

func (e *Engine) Run(scanID string) ([]Group, error) {
	findings, err := e.db.ListFindings(scanID, 2000, 0)
	if err != nil {
		return nil, err
	}
	buckets := map[string]*Group{}
	for _, f := range findings {
		tmpl := templateKey(f.EndpointURL)
		key := f.VulnClass + "|" + tmpl
		g, ok := buckets[key]
		if !ok {
			g = &Group{
				RootCause: f.VulnClass + " on " + tmpl,
				Template:  tmpl,
			}
			buckets[key] = g
		}
		g.Instances = append(g.Instances, f.ID)
		g.Titles = append(g.Titles, f.Title)
		g.Count++
	}
	out := make([]Group, 0, len(buckets))
	for _, g := range buckets {
		if g.Count < 2 {
			continue
		}
		if err := e.db.SaveFindingGroup(scanID, g.RootCause, g); err != nil {
			return nil, err
		}
		if err := e.db.SaveRootCauseCluster(scanID, g.Template, map[string]interface{}{
			"vuln_class": strings.Split(g.RootCause, " on ")[0],
			"instances":  g.Count,
		}); err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, nil
}

var numericPath = regexp.MustCompile(`/\d+`)

func templateKey(url string) string {
	if url == "" {
		return "/"
	}
	parts := strings.Split(url, "/")
	for i, p := range parts {
		if numericPath.MatchString("/"+p) || regexp.MustCompile(`^\d+$`).MatchString(p) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func (e *Engine) MergeGroups(scanID, sourceRoot, targetRoot string) error {
	if sourceRoot == "" || targetRoot == "" || sourceRoot == targetRoot {
		return fmt.Errorf("invalid merge roots")
	}
	groups, err := e.db.ListFindingGroups(scanID, 500)
	if err != nil {
		return err
	}
	var src, tgt *Group
	var srcID int64
	for _, rec := range groups {
		var g Group
		if json.Unmarshal([]byte(rec.GroupJSON), &g) != nil {
			continue
		}
		switch rec.RootCause {
		case sourceRoot:
			src = &g
			srcID = rec.ID
		case targetRoot:
			tgt = &g
		}
	}
	if src == nil || tgt == nil {
		return fmt.Errorf("group not found")
	}
	tgt.Instances = append(tgt.Instances, src.Instances...)
	tgt.Titles = append(tgt.Titles, src.Titles...)
	tgt.Count = len(tgt.Instances)
	if err := e.db.SaveFindingGroup(scanID, targetRoot, tgt); err != nil {
		return err
	}
	return e.db.DeleteFindingGroup(srcID)
}

func (e *Engine) SplitGroup(scanID, rootCause, findingTitle string) error {
	groups, err := e.db.ListFindingGroups(scanID, 500)
	if err != nil {
		return err
	}
	for _, rec := range groups {
		if rec.RootCause != rootCause {
			continue
		}
		var g Group
		if json.Unmarshal([]byte(rec.GroupJSON), &g) != nil {
			return fmt.Errorf("invalid group json")
		}
		idx := -1
		for i, title := range g.Titles {
			if title == findingTitle {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("finding not in group")
		}
		g.Titles = append(g.Titles[:idx], g.Titles[idx+1:]...)
		if idx < len(g.Instances) {
			g.Instances = append(g.Instances[:idx], g.Instances[idx+1:]...)
		}
		g.Count = len(g.Instances)
		_ = e.db.DeleteFindingGroup(rec.ID)
		if g.Count == 0 {
			return nil
		}
		return e.db.SaveFindingGroup(scanID, rootCause, g)
	}
	return fmt.Errorf("group not found")
}
