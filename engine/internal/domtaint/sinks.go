package domtaint

var DOMSinks = []SinkSpec{
	// Code Execution Sinks
	{
		Name:        "eval",
		Category:    SinkCodeExecution,
		Object:      "window",
		Property:    "eval",
		Severity:    "critical",
		Description: "Direct JavaScript code evaluation via eval()",
	},
	{
		Name:        "Function",
		Category:    SinkCodeExecution,
		Object:      "window",
		Property:    "Function",
		Severity:    "critical",
		Description: "Dynamic JavaScript Function constructor",
	},
	{
		Name:        "setTimeout",
		Category:    SinkCodeExecution,
		Object:      "window",
		Property:    "setTimeout",
		Severity:    "high",
		Description: "String evaluation in setTimeout timer",
	},
	{
		Name:        "setInterval",
		Category:    SinkCodeExecution,
		Object:      "window",
		Property:    "setInterval",
		Severity:    "high",
		Description: "String evaluation in setInterval timer",
	},

	// DOM Injection Sinks
	{
		Name:        "Element.innerHTML",
		Category:    SinkDOMInjection,
		Object:      "Element.prototype",
		Property:    "innerHTML",
		Severity:    "high",
		Description: "Unsanitized HTML rendering via innerHTML",
	},
	{
		Name:        "Element.outerHTML",
		Category:    SinkDOMInjection,
		Object:      "Element.prototype",
		Property:    "outerHTML",
		Severity:    "high",
		Description: "Unsanitized HTML rendering via outerHTML",
	},
	{
		Name:        "document.write",
		Category:    SinkDOMInjection,
		Object:      "document",
		Property:    "write",
		Severity:    "high",
		Description: "Direct document HTML stream injection via document.write()",
	},
	{
		Name:        "document.writeln",
		Category:    SinkDOMInjection,
		Object:      "document",
		Property:    "writeln",
		Severity:    "high",
		Description: "Direct document HTML stream injection via document.writeln()",
	},
	{
		Name:        "Element.insertAdjacentHTML",
		Category:    SinkDOMInjection,
		Object:      "Element.prototype",
		Property:    "insertAdjacentHTML",
		Severity:    "high",
		Description: "DOM insertion via insertAdjacentHTML()",
	},

	// Navigation Sinks
	{
		Name:        "location.href",
		Category:    SinkNavigation,
		Object:      "location",
		Property:    "href",
		Severity:    "high",
		Description: "Open redirect or javascript: URL execution via location.href",
	},
	{
		Name:        "location.assign",
		Category:    SinkNavigation,
		Object:      "location",
		Property:    "assign",
		Severity:    "high",
		Description: "Navigation via location.assign()",
	},
	{
		Name:        "location.replace",
		Category:    SinkNavigation,
		Object:      "location",
		Property:    "replace",
		Severity:    "high",
		Description: "Navigation via location.replace()",
	},
	{
		Name:        "window.open",
		Category:    SinkNavigation,
		Object:      "window",
		Property:    "open",
		Severity:    "medium",
		Description: "Window creation via window.open()",
	},

	// Script Loading Sinks
	{
		Name:        "HTMLScriptElement.src",
		Category:    SinkScriptLoad,
		Object:      "HTMLScriptElement.prototype",
		Property:    "src",
		Severity:    "critical",
		Description: "Dynamic external script inclusion via script.src",
	},
	{
		Name:        "HTMLIFrameElement.src",
		Category:    SinkScriptLoad,
		Object:      "HTMLIFrameElement.prototype",
		Property:    "src",
		Severity:    "high",
		Description: "Iframe navigation/injection via iframe.src",
	},
	{
		Name:        "HTMLIFrameElement.srcdoc",
		Category:    SinkScriptLoad,
		Object:      "HTMLIFrameElement.prototype",
		Property:    "srcdoc",
		Severity:    "high",
		Description: "Inline iframe document injection via iframe.srcdoc",
	},
}
