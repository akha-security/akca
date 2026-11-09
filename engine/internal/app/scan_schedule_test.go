package app

import "testing"

func TestPrioritySchedulePrecedesNoisyExposureAndRetainsEveryModule(t *testing.T) {
	priority, full := scheduledModules("priority"), scheduledModules("all")
	index := map[string]int{}
	for i, item := range full {
		if _, exists := index[item.name]; exists {
			t.Fatalf("duplicate module %s", item.name)
		}
		index[item.name] = i
	}
	for _, critical := range []string{"sqli", "xss", "ssrf"} {
		for _, late := range []string{"route_auth_bypass", "sensitive_file_discovery", "backup_archives", "smuggling", "race_condition"} {
			if index[critical] >= index[late] {
				t.Errorf("%s did not precede %s", critical, late)
			}
		}
	}
	for _, core := range []string{"sqli", "xss", "ssrf"} {
		if index[core] >= index["php2shell"] {
			t.Errorf("%s should run before the memory-pressure PHP2Shell assessment", core)
		}
	}
	for _, deferred := range []string{"improper_auth", "open_redirect", "route_auth_bypass", "sensitive_file_discovery"} {
		if index[deferred] < index["sqli"] {
			t.Errorf("%s should wait until core input checks have run", deferred)
		}
	}
	if index["php2shell"] != len(full)-2 {
		t.Errorf("active PHP2Shell should run after broad modules and just before final session work; index=%d len=%d", index["php2shell"], len(full))
	}
	if len(full) != len(fullScanModuleOrder) || full[len(full)-1].name != "session_lifecycle" {
		t.Fatal("catalog coverage or final session cleanup was lost")
	}
	for _, item := range priority {
		if !initialModule(item.name) {
			t.Errorf("noisy module in initial pass: %s", item.name)
		}
	}
}
