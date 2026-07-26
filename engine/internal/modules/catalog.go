package modules

import "sort"

// ModuleCatalog returns all vulnerability module identifiers the engine can run.
func ModuleCatalog() []string {
	seen := map[string]struct{}{}
	out := []string{"xss", "blind_xss", "sqli", "nosql", "ssti", "command_injection"}
	for _, name := range out {
		seen[name] = struct{}{}
	}
	for _, reg := range [][]ModuleDescriptor{GroupARegistry, GroupBRegistry, GroupCRegistry, GroupDRegistry} {
		for _, m := range reg {
			if _, ok := seen[m.Manifest.Name]; ok {
				continue
			}
			seen[m.Manifest.Name] = struct{}{}
			out = append(out, m.Manifest.Name)
		}
	}
	sort.Strings(out)
	return out
}
