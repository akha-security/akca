package workspace

import (
	"encoding/json"
	"fmt"
	"time"
)

// Data model stubs for future multi-user mode. Tables: workspaces, team_members,
// workspace_invitations, audit_log_entries, shared_findings (Phase 2 schema).

type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

type Member struct {
	ID          int64  `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

type Invitation struct {
	ID          int64  `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Email       string `json:"email"`
	Status      string `json:"status"`
}

type AuditEntry struct {
	ID          int64  `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Action      string `json:"action"`
	Actor       string `json:"actor"`
	DetailsJSON string `json:"details_json"`
}

type API struct {
	db WorkspaceDB
}

type WorkspaceDB interface {
	SaveWorkspace(id, name, raw string) error
	ListWorkspaces() ([]Workspace, error)
	SaveMember(workspaceID, raw string) error
	ListMembers(workspaceID string) ([]Member, error)
	SaveAudit(workspaceID, action, actor, details string) error
	CheckPermission(workspaceID, email, perm string) bool
}

func NewAPI(db WorkspaceDB) *API {
	return &API{db: db}
}

func (a *API) CreateWorkspace(name string) (Workspace, error) {
	ws := Workspace{
		ID:        fmt.Sprintf("ws-%d", time.Now().UnixNano()),
		Name:      name,
		Plan:      "team",
		CreatedAt: time.Now().UTC(),
	}
	raw, _ := json.Marshal(ws)
	if err := a.db.SaveWorkspace(ws.ID, name, string(raw)); err != nil {
		return Workspace{}, err
	}
	_ = a.db.SaveAudit(ws.ID, "workspace.created", "system", `{"name":"`+name+`"}`)
	return ws, nil
}

func (a *API) AddMember(workspaceID, email, role string) (Member, error) {
	if !a.db.CheckPermission(workspaceID, "system", "member.manage") {
		return Member{}, fmt.Errorf("permission denied")
	}
	m := Member{WorkspaceID: workspaceID, Email: email, Role: role}
	raw, _ := json.Marshal(m)
	if err := a.db.SaveMember(workspaceID, string(raw)); err != nil {
		return Member{}, err
	}
	return m, nil
}

func (a *API) List(workspaceID string) ([]Member, error) {
	return a.db.ListMembers(workspaceID)
}
