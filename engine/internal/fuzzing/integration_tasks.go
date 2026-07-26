package fuzzing

import "strings"

// BuildIntegrationTasks returns a bounded fuzz path set for integration/lab scans.
// It covers archive, actuator, admin, artifact, and API surfaces without the full wordlist.
func BuildIntegrationTasks(baseURL string) []FuzzTask {
	base := strings.TrimRight(baseURL, "/")
	paths := []struct {
		path string
		cat  Category
	}{
		{"/robots.txt", CategoryGeneral},
		{"/backup.tar.gz", CategoryArchive},
		{"/backup.zip", CategoryArchive},
		{"/admin", CategoryAdmin},
		{"/admin/login", CategoryAdmin},
		{"/actuator/health", CategoryActuator},
		{"/actuator/env", CategoryActuator},
		{"/.git/HEAD", CategoryArtifact},
		{"/.env", CategoryArtifact},
		{"/package.json", CategoryArtifact},
		{"/api/users", CategoryAPI},
		{"/graphql", CategoryAPI},
		{"/swagger.json", CategoryAPI},
		{"/wp-login.php", CategoryFramework},
		{"/server-status", CategoryFramework},
		{"/config.json", CategoryConfig},
		{"/debug", CategoryConfig},
	}
	var tasks []FuzzTask
	for _, item := range paths {
		tasks = append(tasks, FuzzTask{
			URL: base + item.path, Method: "GET", Category: item.cat, Path: item.path,
		})
	}
	return tasks
}
