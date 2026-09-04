package anomaly

import (
	"hash/crc32"
	"regexp"
	"sort"
	"strings"
)

var (
	reTitle   = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	reDivID   = regexp.MustCompile(`(?i)<div[^>]*\sid=["']([^"']+)["']`)
	reClass   = regexp.MustCompile(`(?i)\sclass=["']([^"']+)["']`)
	reComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	reInput   = regexp.MustCompile(`(?i)<input[^>]*\stype=["']([^"']+)["']`)
)

func checksumCRC32(s string) uint32 {
	return crc32.ChecksumIEEE([]byte(s))
}

// ExtractAttributes extracts structural fingerprint attributes from an HTTP response.
func ExtractAttributes(statusCode int, body string, headers map[string]string) AttributeSet {
	attrs := *NewAttributeSet()

	// 1. Status Code
	attrs.Set(STATUS_CODE, uint32(statusCode))

	// 2. Line count & Word count
	attrs.Set(LINE_COUNT, uint32(strings.Count(body, "\n")))
	attrs.Set(WORD_COUNT, uint32(strings.Count(body, " ")))
	attrs.Set(CONTENT_LENGTH, uint32(len(body)))

	// 3. Body content hashes
	attrs.Set(WHOLE_BODY_CONTENT, checksumCRC32(body))

	// Limited body content (first 1024 + last 1024 bytes)
	bodyBytes := []byte(body)
	bodyLen := len(bodyBytes)
	h := crc32.NewIEEE()
	if bodyLen < 2048 {
		h.Write(bodyBytes)
	} else {
		h.Write(bodyBytes[:1024])
		h.Write(bodyBytes[bodyLen-1024:])
	}
	attrs.Set(LIMITED_BODY_CONTENT, h.Sum32())

	// Initial body content (first 32 bytes)
	initLen := 32
	if bodyLen < initLen {
		initLen = bodyLen
	}
	attrs.Set(INITIAL_BODY_CONTENT, crc32.ChecksumIEEE(bodyBytes[:initLen]))

	// 4. Headers
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		switch lowerK {
		case "content-type":
			split := strings.Split(v, ";")
			attrs.Set(CONTENT_TYPE, checksumCRC32(strings.TrimSpace(split[0])))
		case "content-location":
			attrs.Set(CONTENT_LOCATION, checksumCRC32(v))
		case "etag":
			attrs.Set(ETAG_HEADER, checksumCRC32(v))
		case "server":
			attrs.Set(SERVER_HEADER, checksumCRC32(v))
		case "location":
			attrs.Set(LOCATION, checksumCRC32(v))
		case "last-modified":
			attrs.Set(LAST_MODIFIED_HEADER, checksumCRC32(v))
		case "set-cookie":
			parts := strings.Split(v, ";")
			cName := strings.Split(parts[0], "=")[0]
			attrs.Set(SET_COOKIE_NAMES, checksumCRC32(strings.TrimSpace(cName)))
		}
	}

	// 5. HTML Elements
	if titleMatch := reTitle.FindStringSubmatch(body); len(titleMatch) > 1 {
		attrs.Set(PAGE_TITLE, checksumCRC32(strings.TrimSpace(titleMatch[1])))
	}

	divMatches := reDivID.FindAllStringSubmatch(body, 20)
	if len(divMatches) > 0 {
		var divIDs []string
		for _, m := range divMatches {
			if len(m) > 1 {
				divIDs = append(divIDs, m[1])
			}
		}
		sort.Strings(divIDs)
		attrs.Set(DIV_IDS, checksumCRC32(strings.Join(divIDs, "|")))
	}

	classMatches := reClass.FindAllStringSubmatch(body, 30)
	if len(classMatches) > 0 {
		var classes []string
		for _, m := range classMatches {
			if len(m) > 1 {
				classes = append(classes, m[1])
			}
		}
		sort.Strings(classes)
		attrs.Set(CSS_CLASSES, checksumCRC32(strings.Join(classes, "|")))
	}

	inputMatches := reInput.FindAllStringSubmatch(body, 20)
	if len(inputMatches) > 0 {
		var inputTypes []string
		for _, m := range inputMatches {
			if len(m) > 1 {
				inputTypes = append(inputTypes, strings.ToLower(m[1]))
			}
		}
		sort.Strings(inputTypes)
		attrs.Set(NON_HIDDEN_FORM_INPUT_TYPES, checksumCRC32(strings.Join(inputTypes, "|")))
	}

	commentMatches := reComment.FindAllStringSubmatch(body, 10)
	if len(commentMatches) > 0 {
		var comments []string
		for _, m := range commentMatches {
			if len(m) > 1 {
				comments = append(comments, m[1])
			}
		}
		sort.Strings(comments)
		attrs.Set(COMMENTS, checksumCRC32(strings.Join(comments, "|")))
	}

	return attrs
}
