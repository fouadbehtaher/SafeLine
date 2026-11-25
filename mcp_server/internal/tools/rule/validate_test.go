package rule

import (
	"strings"
	"testing"
)

func TestValidateRuleParams(t *testing.T) {
	longName := strings.Repeat("a", maxRuleNameLen+1)
	tooMany := make([]string, maxRuleEntries+1)
	for i := range tooMany {
		tooMany[i] = "1.2.3.4"
	}

	tests := []struct {
		name    string
		rule    string
		ips     []string
		uris    []string
		wantErr string // empty means valid
	}{
		{"ip only", "block-scanner", []string{"203.0.113.7"}, nil, ""},
		{"ipv6", "block-v6", []string{"2001:db8::1"}, nil, ""},
		{"uri only", "block-admin", nil, []string{"/wp-login.php"}, ""},
		{"both", "mixed", []string{"203.0.113.7", "198.51.100.2"}, []string{"/a", "/b/c"}, ""},
		{"name with spaces trimmed", "  ok  ", []string{"203.0.113.7"}, nil, ""},
		{"empty name", "", []string{"203.0.113.7"}, nil, "name is required"},
		{"blank name", "   ", []string{"203.0.113.7"}, nil, "name is required"},
		{"long name", longName, []string{"203.0.113.7"}, nil, "name is longer"},
		{"control char in name", "a\nb", []string{"203.0.113.7"}, nil, "control characters"},
		{"no pattern at all", "empty", nil, nil, "at least one"},
		{"empty slices", "empty", []string{}, []string{}, "at least one"},
		{"bad ip", "x", []string{"not-an-ip"}, nil, "not a valid IP"},
		{"ip with port", "x", []string{"1.2.3.4:80"}, nil, "not a valid IP"},
		{"ip with injected text", "x", []string{"1.2.3.4; drop"}, nil, "not a valid IP"},
		{"octal-looking ip", "x", []string{"010.1.1.1"}, nil, "not a valid IP"},
		{"cidr rejected", "x", []string{"10.0.0.0/8"}, nil, "CIDR"},
		{"unspecified ip", "x", []string{"0.0.0.0"}, nil, "unspecified"},
		{"unspecified v6", "x", []string{"::"}, nil, "unspecified"},
		{"too many ips", "x", tooMany, nil, "at most"},
		{"uri without slash", "x", nil, []string{"admin"}, "must start with /"},
		{"empty uri", "x", nil, []string{""}, "must start with /"},
		{"uri with query", "x", nil, []string{"/a?b=1"}, "query string"},
		{"uri with fragment", "x", nil, []string{"/a#b"}, "query string"},
		{"uri with space", "x", nil, []string{"/a b"}, "whitespace"},
		{"uri with newline", "x", nil, []string{"/a\nb"}, "whitespace"},
		{"uri too long", "x", nil, []string{"/" + strings.Repeat("a", maxURILen)}, "longer than"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRuleParams(tt.rule, tt.ips, tt.uris)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestToolsUseSharedValidation(t *testing.T) {
	if err := (&CreateBlacklistRule{}).Validate(CreateBlacklistRuleParams{Name: "x"}); err == nil {
		t.Fatal("blacklist: rule without ip or uri must be rejected")
	}
	if err := (&CreateWhitelistRule{}).Validate(CreateWhitelistRuleParams{Name: "x"}); err == nil {
		t.Fatal("whitelist: rule without ip or uri must be rejected")
	}
	if err := (&CreateBlacklistRule{}).Validate(CreateBlacklistRuleParams{Name: "x", IP: []string{"203.0.113.7"}}); err != nil {
		t.Fatalf("blacklist: valid params rejected: %v", err)
	}
	if err := (&CreateWhitelistRule{}).Validate(CreateWhitelistRuleParams{Name: "x", URINoQuery: []string{"/ok"}}); err != nil {
		t.Fatalf("whitelist: valid params rejected: %v", err)
	}
}
