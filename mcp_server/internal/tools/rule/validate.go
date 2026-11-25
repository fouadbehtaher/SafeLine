package rule

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

const (
	maxRuleNameLen = 64
	maxRuleEntries = 100
	maxURILen      = 2048
)

// validateRuleParams checks the arguments shared by the blacklist and
// whitelist tools before anything is sent to SafeLine. The values usually come
// from an LLM or a chat message, and a bad deny rule can block real traffic,
// so mistakes are rejected here with a clear message instead of being sent on.
func validateRuleParams(name string, ips, uris []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len([]rune(name)) > maxRuleNameLen {
		return fmt.Errorf("name is longer than %d characters", maxRuleNameLen)
	}
	if hasControlChars(name) {
		return fmt.Errorf("name contains control characters")
	}

	if len(ips) == 0 && len(uris) == 0 {
		return fmt.Errorf("at least one of ip or uri_no_query is required")
	}
	if len(ips) > maxRuleEntries || len(uris) > maxRuleEntries {
		return fmt.Errorf("at most %d entries are allowed per list", maxRuleEntries)
	}

	for _, value := range ips {
		if strings.Contains(value, "/") {
			return fmt.Errorf("ip %q: CIDR ranges are not supported by this tool, give single IP addresses", value)
		}
		parsed := net.ParseIP(strings.TrimSpace(value))
		if parsed == nil {
			return fmt.Errorf("ip %q is not a valid IP address", value)
		}
		if parsed.IsUnspecified() {
			return fmt.Errorf("ip %q is the unspecified address", value)
		}
	}

	for _, value := range uris {
		if value == "" || value[0] != '/' {
			return fmt.Errorf("uri_no_query %q must start with /", value)
		}
		if len(value) > maxURILen {
			return fmt.Errorf("uri_no_query is longer than %d characters", maxURILen)
		}
		if strings.ContainsAny(value, "?#") {
			return fmt.Errorf("uri_no_query %q must not contain a query string or fragment", value)
		}
		if hasControlChars(value) || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
			return fmt.Errorf("uri_no_query %q contains whitespace or control characters", value)
		}
	}
	return nil
}

func hasControlChars(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}
