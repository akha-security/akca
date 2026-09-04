package domtaint

import (
	"fmt"
)

// GenerateHarness produces the JavaScript instrumentation payload to be evaluated
// on new document creation in the headless browser before page scripts run.
func GenerateHarness(canary string) string {
	return fmt.Sprintf(`(function() {
	if (window.__akca_taint_installed) return;
	window.__akca_taint_installed = true;
	window.__akca_taint_log = [];

	const canary = %q;

	function logHit(sinkName, category, severity, value) {
		const valStr = String(value || "");
		if (canary && valStr.indexOf(canary) === -1) return;
		try {
			const stack = new Error().stack || "";
			window.__akca_taint_log.push({
				sink: sinkName,
				category: category,
				severity: severity,
				sink_value: valStr.substring(0, 1024),
				stack_trace: stack,
				url: window.location.href,
				canary: canary,
				timestamp: Date.now()
			});
		} catch (e) {}
	}

	// 1. Hook eval
	const origEval = window.eval;
	window.eval = function(code) {
		logHit("eval", "code_execution", "critical", code);
		return origEval.apply(this, arguments);
	};

	// 2. Hook setTimeout / setInterval with string code
	const origSetTimeout = window.setTimeout;
	window.setTimeout = function(handler, timeout) {
		if (typeof handler === "string") {
			logHit("setTimeout", "code_execution", "high", handler);
		}
		return origSetTimeout.apply(this, arguments);
	};

	const origSetInterval = window.setInterval;
	window.setInterval = function(handler, timeout) {
		if (typeof handler === "string") {
			logHit("setInterval", "code_execution", "high", handler);
		}
		return origSetInterval.apply(this, arguments);
	};

	// 3. Hook document.write & writeln
	const origWrite = document.write;
	document.write = function(content) {
		logHit("document.write", "dom_injection", "high", content);
		return origWrite.apply(this, arguments);
	};

	const origWriteln = document.writeln;
	document.writeln = function(content) {
		logHit("document.writeln", "dom_injection", "high", content);
		return origWriteln.apply(this, arguments);
	};

	// 4. Hook Element.prototype.innerHTML
	const origInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
	if (origInnerHTMLDesc && origInnerHTMLDesc.set) {
		Object.defineProperty(Element.prototype, "innerHTML", {
			set: function(val) {
				logHit("Element.innerHTML", "dom_injection", "high", val);
				return origInnerHTMLDesc.set.call(this, val);
			},
			get: origInnerHTMLDesc.get
		});
	}

	// 5. Hook Element.prototype.outerHTML
	const origOuterHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, "outerHTML");
	if (origOuterHTMLDesc && origOuterHTMLDesc.set) {
		Object.defineProperty(Element.prototype, "outerHTML", {
			set: function(val) {
				logHit("Element.outerHTML", "dom_injection", "high", val);
				return origOuterHTMLDesc.set.call(this, val);
			},
			get: origOuterHTMLDesc.get
		});
	}

	// 6. Hook HTMLScriptElement.prototype.src
	const origScriptSrcDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, "src");
	if (origScriptSrcDesc && origScriptSrcDesc.set) {
		Object.defineProperty(HTMLScriptElement.prototype, "src", {
			set: function(val) {
				logHit("HTMLScriptElement.src", "script_load", "critical", val);
				return origScriptSrcDesc.set.call(this, val);
			},
			get: origScriptSrcDesc.get
		});
	}
})();`, canary)
}
