package crawler

import (
	"fmt"
)

// SmartActionConfig defines settings for browser-based interactive crawling.
type SmartActionConfig struct {
	MaxActionsPerStep int  `json:"max_actions_per_step"`
	FillForms         bool `json:"fill_forms"`
	TraverseShadowDOM bool `json:"traverse_shadow_dom"`
	TriggerHover      bool `json:"trigger_hover"`
}

// DefaultSmartActionConfig returns optimal settings for SPA crawling.
func DefaultSmartActionConfig() SmartActionConfig {
	return SmartActionConfig{
		MaxActionsPerStep: 25,
		FillForms:         true,
		TraverseShadowDOM: true,
		TriggerHover:      true,
	}
}

// GenerateSmartActionScript returns a self-executing JavaScript payload to be evaluated in
// the browser page context to simulate realistic user clicks and form interactions in SPAs.
func GenerateSmartActionScript(cfg SmartActionConfig) string {
	return fmt.Sprintf(`(function() {
	if (window.__akca_smart_action_done) return [];
	window.__akca_smart_action_done = true;

	const capturedURLs = new Set();
	const maxActions = %d;
	let actionCount = 0;

	// Helper to collect all DOM elements including Shadow DOM
	function getAllElements(root = document) {
		const elements = [];
		function traverse(node) {
			if (!node || node.nodeType !== Node.ELEMENT_NODE) return;
			elements.push(node);
			if (node.shadowRoot) {
				Array.from(node.shadowRoot.children).forEach(traverse);
			}
			Array.from(node.children).forEach(traverse);
		}
		Array.from(root.children).forEach(traverse);
		return elements;
	}

	const allNodes = getAllElements();

	// 1. Auto-fill Form Inputs with realistic test values
	if (%t) {
		allNodes.forEach(el => {
			if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') {
				const type = (el.type || 'text').toLowerCase();
				const name = (el.name || el.id || '').toLowerCase();

				if (type === 'email' || name.includes('email') || name.includes('mail')) {
					el.value = 'crawler@akca-test.local';
				} else if (type === 'password' || name.includes('pass') || name.includes('pwd')) {
					el.value = 'AkcaPass123!#';
				} else if (type === 'number' || type === 'tel' || name.includes('phone') || name.includes('amount') || name.includes('count')) {
					el.value = '100';
				} else if (type === 'checkbox' || type === 'radio') {
					el.checked = true;
				} else if (type === 'text' || type === 'search' || el.tagName === 'TEXTAREA') {
					el.value = 'akca_crawler_query';
				}
				el.dispatchEvent(new Event('input', { bubbles: true }));
				el.dispatchEvent(new Event('change', { bubbles: true }));
			}
		});
	}

	// 2. Trigger Buttons, Tabs, Dropdowns & Actionable Elements
	for (const el of allNodes) {
		if (actionCount >= maxActions) break;

		const tag = el.tagName;
		const role = (el.getAttribute('role') || '').toLowerCase();
		const isClickable = tag === 'BUTTON' || tag === 'A' || role === 'button' || role === 'tab' ||
			role === 'menuitem' || el.hasAttribute('onclick') || el.classList.contains('btn') ||
			el.classList.contains('button') || el.classList.contains('tab');

		if (isClickable && !el.disabled && el.offsetParent !== null) {
			try {
				if (%t) {
					el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
				}
				el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
				el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
				el.click();
				actionCount++;
			} catch (e) {}
		}
	}

	// 3. Extract any newly generated link targets from DOM
	getAllElements().forEach(el => {
		if (el.tagName === 'A' && el.href) {
			capturedURLs.add(el.href);
		} else if (el.hasAttribute('data-href')) {
			capturedURLs.add(el.getAttribute('data-href'));
		} else if (el.hasAttribute('data-url')) {
			capturedURLs.add(el.getAttribute('data-url'));
		}
	});

	return Array.from(capturedURLs);
})();`, cfg.MaxActionsPerStep, cfg.FillForms, cfg.TriggerHover)
}
