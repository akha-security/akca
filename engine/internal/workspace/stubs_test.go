package workspace

import (
	"encoding/json"
	"testing"
)

type memDB struct {
	workspaces map[string]string
	members    map[string][]string
	audit      []string
}

func (m *memDB) SaveWorkspace(id, name, raw string) error {
	m.workspaces[id] = raw
	return nil
}
func (m *memDB) ListWorkspaces() ([]Workspace, error) {
	var out []Workspace
	for _, raw := range m.workspaces {
		var w Workspace
		_ = json.Unmarshal([]byte(raw), &w)
		out = append(out, w)
	}
	return out, nil
}
func (m *memDB) SaveMember(workspaceID, raw string) error {
	m.members[workspaceID] = append(m.members[workspaceID], raw)
	return nil
}
func (m *memDB) ListMembers(workspaceID string) ([]Member, error) {
	var out []Member
	for _, raw := range m.members[workspaceID] {
		var mem Member
		_ = json.Unmarshal([]byte(raw), &mem)
		out = append(out, mem)
	}
	return out, nil
}
func (m *memDB) SaveAudit(workspaceID, action, actor, details string) error {
	m.audit = append(m.audit, action)
	return nil
}
func (m *memDB) CheckPermission(workspaceID, email, perm string) bool {
	_ = workspaceID
	_ = email
	_ = perm
	return true
}

func TestWorkspaceCRUDStub(t *testing.T) {
	db := &memDB{workspaces: map[string]string{}, members: map[string][]string{}}
	api := NewAPI(db)
	ws, err := api.CreateWorkspace("Akca Team")
	if err != nil || ws.ID == "" {
		t.Fatalf("create failed: %v", err)
	}
	_, err = api.AddMember(ws.ID, "analyst@test", "admin")
	if err != nil {
		t.Fatal(err)
	}
	members, err := api.List(ws.ID)
	if err != nil || len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
}
