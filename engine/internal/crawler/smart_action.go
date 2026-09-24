package crawler

import "fmt"

type SmartActionConfig struct {
	MaxActionsPerStep int  `json:"max_actions_per_step"`
	FillForms         bool `json:"fill_forms"`
	TraverseShadowDOM bool `json:"traverse_shadow_dom"`
	TriggerHover      bool `json:"trigger_hover"`
}

func DefaultSmartActionConfig() SmartActionConfig {
	return SmartActionConfig{MaxActionsPerStep: 12, TraverseShadowDOM: true}
}

// Discovery never fills or submits forms. Only explicitly marked navigation
// tabs and collapsed panels are activated, at most once per document.
func GenerateSmartActionScript(cfg SmartActionConfig) string {
	limit := cfg.MaxActionsPerStep
	if limit < 0 {
		limit = 0
	}
	if limit > 25 {
		limit = 25
	}
	return fmt.Sprintf(`(async function() {
 if (window.__akca_smart_action_done) return [];
 window.__akca_smart_action_done = true;
 function nodes(root) {
  const out = Array.from(root.querySelectorAll('*'));
  if (%t) for (const el of [...out]) if (el.shadowRoot) out.push(...nodes(el.shadowRoot));
  return out;
 }
 let count = 0;
 for (const el of nodes(document)) {
  if (count >= %d) break;
  if (el.tagName !== 'BUTTON' || el.type !== 'button' || el.disabled || el.offsetParent === null || el.closest('form')) continue;
  if (!el.hasAttribute('aria-controls')) continue;
  if (el.getAttribute('role') !== 'tab' && el.getAttribute('aria-expanded') !== 'false') continue;
  if (/delete|remove|logout|sign.out|purchase|pay|submit|confirm/i.test(el.textContent + ' ' + el.getAttribute('aria-label'))) continue;
  el.click(); count++;
  await new Promise(resolve => setTimeout(resolve, 100));
 }
 return nodes(document).filter(el => el.tagName === 'A' && el.href).map(el => el.href);
})();`, cfg.TraverseShadowDOM, limit)
}
