package safemutation

import "testing"

func TestDefaultPolicyRequiresCleanupAndBlocksDestructiveActions(t *testing.T) {
	guard := NewGuard(DefaultPolicy())
	if _, err := guard.Begin(Operation{ID: "delete-account", Risk: PotentiallyDestructive}, "before"); err == nil {
		t.Fatal("destructive action must be disabled by default")
	}
	if _, err := guard.Begin(Operation{ID: "update-profile", Risk: ReversibleWrite}, "before"); err == nil {
		t.Fatal("reversible write without cleanup must be rejected")
	}
	tx, err := guard.Begin(Operation{
		ID: "update-profile", ResourceID: "profile:7", Risk: ReversibleWrite, CleanupDefined: true,
	}, "before")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Finish(tx.ID, "after", false); err == nil {
		t.Fatal("cleanup failure must be surfaced")
	}
}

func TestMutationRequiresSnapshotAndDoesNotRepeatResource(t *testing.T) {
	guard := NewGuard(DefaultPolicy())
	op := Operation{
		ID: "update-profile", ResourceID: "profile:7",
		Risk: ReversibleWrite, CleanupDefined: true,
	}
	if _, err := guard.Begin(op, ""); err == nil {
		t.Fatal("write without a real before-state snapshot must be rejected")
	}
	tx, err := guard.Begin(op, "before-hash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Finish(tx.ID, "after-hash", true); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Begin(op, "before-hash"); err == nil {
		t.Fatal("the same production resource must not be mutated twice in one run")
	}
}
