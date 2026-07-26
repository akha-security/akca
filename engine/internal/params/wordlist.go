package params

// Wordlist returns the built-in parameter name list (500+ entries).
func Wordlist() []string {
	if len(builtinWordlist) > 0 {
		out := make([]string, len(builtinWordlist))
		copy(out, builtinWordlist)
		return out
	}
	return generateWordlist()
}

var builtinWordlist []string

func init() {
	builtinWordlist = generateWordlist()
}

func generateWordlist() []string {
	base := []string{
		"id", "uid", "user", "user_id", "userid", "username", "email", "password", "pass", "pwd",
		"token", "access_token", "refresh_token", "api_key", "apikey", "key", "secret", "auth",
		"session", "sessionid", "sid", "csrf", "csrf_token", "xsrf", "nonce", "state", "code",
		"redirect", "redirect_uri", "callback", "return", "next", "url", "uri", "path", "file",
		"filename", "name", "q", "query", "search", "s", "term", "keyword", "filter", "sort",
		"order", "page", "p", "limit", "offset", "start", "count", "size", "per_page",
		"category", "cat", "type", "action", "cmd", "command", "do", "op", "operation", "mode",
		"view", "format", "output", "lang", "locale", "language", "country", "region", "currency",
		"amount", "price", "total", "qty", "quantity", "product", "product_id", "item", "item_id",
		"order_id", "invoice", "invoice_id", "customer", "customer_id", "account", "account_id",
		"role", "roles", "group", "group_id", "team", "team_id", "org", "org_id", "tenant",
		"tenant_id", "domain", "host", "hostname", "port", "protocol", "scheme", "method",
		"version", "v", "api", "endpoint", "resource", "ref", "reference", "parent", "parent_id",
		"child", "child_id", "from", "to", "date", "start_date", "end_date", "since", "until",
		"created", "updated", "modified", "deleted", "status", "active", "enabled", "disabled",
		"visible", "hidden", "public", "private", "scope", "scopes", "permission", "permissions",
		"grant_type", "client_id", "client_secret", "response_type", "approval_prompt",
		"subscription", "plan", "coupon", "discount", "promo", "promocode", "gift", "card",
		"number", "cvv", "exp", "zip", "postal", "address", "street", "city", "phone", "mobile",
		"message", "msg", "text", "body", "content", "data", "payload", "json", "xml", "html",
		"template", "theme", "skin", "color", "width", "height", "x", "y", "z", "lat", "lon",
		"latitude", "longitude", "geo", "location", "tag", "tags", "label", "labels", "comment",
		"comments", "note", "notes", "title", "description", "desc", "summary", "details",
		"debug", "test", "preview", "draft", "publish", "save", "submit", "confirm", "verify",
		"validate", "check", "upload", "download", "import", "export", "sync", "async", "callback_url",
		"webhook", "notify", "notification", "alert", "subscribe", "unsubscribe", "follow",
		"share", "like", "vote", "rating", "score", "rank", "level", "stage", "step", "phase",
		"tab", "section", "module", "component", "widget", "plugin", "extension", "addon",
		"channel", "source", "medium", "campaign", "utm_source", "utm_medium", "utm_campaign",
		"utm_term", "utm_content", "gclid", "fbclid", "msclkid", "ref_id", "affiliate", "partner",
		"vendor", "supplier", "manufacturer", "brand", "model", "serial", "sku", "barcode", "isbn",
		"ean", "upc", "hash", "signature", "sig", "checksum", "crc", "etag", "cache", "nocache",
		"reload", "force", "reset", "clear", "flush", "purge", "refresh", "rev", "revision",
		"build", "commit", "branch", "repo", "repository", "project", "workspace", "folder",
		"directory", "bucket", "object", "blob", "asset", "media", "image", "img", "avatar",
		"icon", "logo", "banner", "thumbnail", "video", "audio", "stream", "channel_id",
		"playlist", "track", "album", "artist", "genre", "year", "month", "day", "hour", "minute",
		"second", "timezone", "tz", "timestamp", "ts", "epoch", "ttl", "expires", "expiry",
		"duration", "interval", "frequency", "repeat", "loop", "cycle", "batch", "chunk", "part",
		"segment", "fragment", "packet", "frame", "block", "slot", "index", "position", "cursor",
		"marker", "pointer", "handle", "ticket", "request_id", "trace_id", "span_id", "correlation_id",
		"transaction_id", "payment_id", "charge_id", "intent_id", "setup_intent", "customer_email",
		"billing", "shipping", "tax", "vat", "fee", "tip", "balance", "credit", "debit", "wallet",
		"iban", "swift", "bic", "routing", "sort_code", "ssn", "tax_id", "vat_id", "company",
		"company_id", "employer", "employee", "staff", "member", "membership", "invite", "invitation",
		"referral", "referrer", "affiliate_id", "agent", "broker", "dealer", "distributor", "reseller",
		"merchant", "store", "shop", "market", "listing", "offer", "bid", "ask", "quote", "estimate",
		"forecast", "target", "goal", "objective", "milestone", "deadline", "priority", "severity",
		"impact", "risk", "threat", "vulnerability", "issue", "bug", "defect", "incident", "case",
		"ticket_id", "support", "help", "faq", "kb", "article", "post", "post_id", "blog", "story",
		"feed", "timeline", "event", "event_id", "calendar", "schedule", "appointment", "booking",
		"reservation", "slot_id", "room", "room_id", "seat", "seat_id", "table", "table_id", "guest",
		"guests", "adult", "child_count", "infant", "pet", "vehicle", "plate", "vin", "make",
	}

	seen := map[string]struct{}{}
	var out []string
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for _, n := range base {
		add(n)
	}
	prefixes := []string{"user", "account", "item", "order", "product", "api", "meta", "custom", "input", "param"}
	suffixes := []string{"id", "name", "key", "token", "code", "value", "data", "type", "status", "flag"}
	for _, p := range prefixes {
		for _, s := range suffixes {
			add(p + "_" + s)
			add(p + s)
		}
	}
	for i := 0; i < 100; i++ {
		add("param" + itoa(i))
		add("field" + itoa(i))
		add("arg" + itoa(i))
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	n := i
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}

func WordlistSize() int {
	return len(builtinWordlist)
}
