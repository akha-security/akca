package domtaint

var DOMSources = []SourceSpec{
	{
		Name:        "location.hash",
		Category:    SourceURL,
		Expression:  "window.location.hash",
		Description: "URL fragment identifier (e.g. #payload)",
	},
	{
		Name:        "location.search",
		Category:    SourceURL,
		Expression:  "window.location.search",
		Description: "URL query parameters (e.g. ?q=payload)",
	},
	{
		Name:        "location.href",
		Category:    SourceURL,
		Expression:  "window.location.href",
		Description: "Full URL string",
	},
	{
		Name:        "location.pathname",
		Category:    SourceURL,
		Expression:  "window.location.pathname",
		Description: "URL path component",
	},
	{
		Name:        "document.referrer",
		Category:    SourceEnvironment,
		Expression:  "document.referrer",
		Description: "HTTP Referer URL of the referring page",
	},
	{
		Name:        "window.name",
		Category:    SourceEnvironment,
		Expression:  "window.name",
		Description: "Window context name property",
	},
	{
		Name:        "postMessage",
		Category:    SourceMessage,
		Expression:  "window.addEventListener('message', event => event.data)",
		Description: "Cross-document messaging event data",
	},
	{
		Name:        "localStorage",
		Category:    SourceStorage,
		Expression:  "window.localStorage.getItem",
		Description: "Client-side HTML5 LocalStorage",
	},
	{
		Name:        "sessionStorage",
		Category:    SourceStorage,
		Expression:  "window.sessionStorage.getItem",
		Description: "Client-side HTML5 SessionStorage",
	},
	{
		Name:        "document.cookie",
		Category:    SourceStorage,
		Expression:  "document.cookie",
		Description: "Client-accessible document cookies",
	},
}
