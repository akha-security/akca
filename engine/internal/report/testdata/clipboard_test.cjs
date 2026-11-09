const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('templates.go', 'utf8');
const start = source.indexOf('function copyToClipboard(');
const end = source.indexOf("document.addEventListener('DOMContentLoaded'", start);
const code = source.slice(start, end);
// Combining a category with severity must remain reversible through All.
const filterCode = source.slice(source.indexOf("let activeSeverity ="), source.indexOf('function selectEvidenceTab('));
function filterElement(attributes, textContent = '') {
  const classes = new Set();
  return {textContent, style: {}, getAttribute: name => attributes[name],
    setAttribute(name, value) {attributes[name] = value;},
    classList: {toggle(name, enabled) {if (enabled) classes.add(name); else classes.delete(name);}}};
}
const cards = [
  filterElement({'data-class': 'sqli', 'data-severity': 'high'}, 'SQL injection category'),
  filterElement({'data-class': 'cors', 'data-severity': 'medium'}, 'CORS origin policy')
];
const category = filterElement({'data-vclass': 'sqli'});
const severityButtons = ['all', 'high', 'medium'].map(sev => filterElement({'data-sev': sev}));
const search = {value: ''}, status = {textContent: ''};
const filterDocument = {
  querySelectorAll(selector) {
    return selector === '.finding' ? cards : selector === '.category-chip' ? [category] : severityButtons;
  },
  getElementById(id) {
    return id === 'vulnSearch' ? search : id === 'filterStatus' ? status : {scrollIntoView() {}};
  }
};
const filterContext = {document: filterDocument};
vm.createContext(filterContext);
vm.runInContext(filterCode, filterContext);
filterContext.setClassFilter('sqli');
assert.equal(cards[0].style.display, 'block');
assert.equal(cards[1].style.display, 'none');
assert.equal(category.getAttribute('aria-pressed'), 'true');
filterContext.setSeverityFilter('medium', severityButtons[2]);
assert.equal(status.textContent, '0 findings shown');
filterContext.setSeverityFilter('all', severityButtons[0]);
assert.equal(status.textContent, '2 findings shown');
assert.equal(category.getAttribute('aria-pressed'), 'false');
filterContext.setClassFilter('sqli');
filterContext.setClassFilter('sqli');
assert.equal(status.textContent, '2 findings shown');
search.value = 'origin';
filterContext.applyFilters();
assert.equal(cards[0].style.display, 'none');
assert.equal(cards[1].style.display, 'block');
// Exercise the request/response controls without a browser or real clipboard.
const evidenceCode = source.slice(source.indexOf('function selectEvidenceTab('), source.indexOf('function showToast('));
const evidenceContext = {};
vm.createContext(evidenceContext);
vm.runInContext(evidenceCode, evidenceContext);
function element(name) {
  const classes = new Set();
  const attributes = {};
  return {classes, attributes, getAttribute: () => name,
    setAttribute: (key, value) => {attributes[key] = value;},
    classList: {toggle(key, force) {
      const enabled = force === undefined ? !classes.has(key) : force;
      if (enabled) classes.add(key); else classes.delete(key);
      return enabled;
    }}};
}
const tabs = ['request', 'response', 'both'].map(element);
const panels = ['request', 'response'].map(element);
const detail = {querySelectorAll: selector => selector === '.traffic-tab' ? tabs : panels};
for (const selected of ['response', 'both', 'request']) {
  evidenceContext.selectEvidenceTab({closest: () => detail}, selected);
  panels.forEach((panel, index) => assert.equal(panel.classes.has('active'), selected === 'both' || selected === ['request', 'response'][index]));
  tabs.forEach((tab, index) => assert.equal(tab.attributes['aria-pressed'], String(selected === ['request', 'response', 'both'][index])));
}
const expand = element('expand');
expand.closest = () => panels[0];
evidenceContext.toggleEvidenceSize(expand);
assert.equal(expand.attributes['aria-expanded'], 'false');
assert.equal(expand.textContent, 'Show full content');
evidenceContext.toggleEvidenceSize(expand);
assert.equal(expand.attributes['aria-expanded'], 'true');
assert.equal(expand.textContent, 'Compact view');
async function run(mode) {
  const raw = 'HTTP/1.1 302\nSet-Cookie: session=raw-token\n\n<example>&unmasked';
  let clipboard = '', selected, removed = false;
  const notices = [];
  const pre = {textContent: raw};
  const header = {nextElementSibling: pre};
  const button = {nextElementSibling: null, innerHTML: 'Copy Response',
    getAttribute: () => null, closest: () => header,
    classList: {add() {}, remove() {}}, focus() {}};
  const document = {activeElement: button, body: {appendChild() {}},
    createElement() {return {style: {}, select() {selected = this.value;}, remove() {removed = true;}};},
    execCommand(command) {assert.equal(command, 'copy'); if (mode === 'denied') return false; clipboard = selected; return true;}};
  const navigator = {};
  if (mode === 'modern') navigator.clipboard = {writeText: async text => {clipboard = text;}};
  if (mode === 'rejected') navigator.clipboard = {writeText: async () => {throw Error('permission denied');}};
  const context = {navigator, document, showToast: text => notices.push(text), setTimeout() {}, Promise};
  vm.createContext(context);vm.runInContext(code, context);
  await context.copyToClipboard(button);
  if (mode === 'denied') {assert.equal(clipboard, ''); assert.deepEqual(notices, ['Failed to copy']);}
  else {assert.equal(clipboard, raw); assert.match(notices[0], /Copied/);}
  if (mode !== 'modern') assert.equal(removed, true);
}
(async () => {for (const mode of ['modern', 'unavailable', 'rejected', 'denied']) await run(mode); console.log('clipboard: 4 paths passed');})().catch(e => {console.error(e);process.exitCode = 1;});
