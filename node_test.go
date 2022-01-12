package chainpoint

import (
	"net/http"
	"sort"
	"testing"
	"time"
)

func TestValidCoreURI(t *testing.T) {
	testCases := map[string]struct {
		uri string
		exp bool
	}{
		"Empty":             {"", false},
		"No scheme":         {"a.chainpoint.org", false},
		"Wrong scheme":      {"http://a.chainpoint.org", false},
		"Wrong subdomain":   {"https://1.chainpoint.org", false},
		"Wrong subdomain 2": {"https://a1.chainpoint.org", false},
		"Valid":             {"https://a.chainpoint.org", true},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := validCoreURI(tc.uri), tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestCores(t *testing.T) {
	c := http.DefaultClient
	s, err := New(c)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	testCases := map[string]struct {
		uris []string
		num  int
		exp  []string
	}{
		"One":               {[]string{"a.chainpoint.org"}, 3, []string{"https://a.chainpoint.org"}},
		"Two":               {[]string{"a.chainpoint.org", "b.chainpoint.org"}, 3, []string{"https://a.chainpoint.org", "https://b.chainpoint.org"}},
		"Three":             {[]string{"a.chainpoint.org", "b.chainpoint.org", "c.chainpoint.org"}, 3, []string{"https://a.chainpoint.org", "https://b.chainpoint.org", "https://c.chainpoint.org"}},
		"Four with invalid": {[]string{"a.chainpoint.org", "b.chainpoint.org", "c.chainpoint.org", "1.chainpoint.org"}, 3, []string{"https://a.chainpoint.org", "https://b.chainpoint.org", "https://c.chainpoint.org"}},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			s.lookupTXT = func(name string) ([]string, error) { return tc.uris, nil }
			got, err := s.Cores(tc.num)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if exp := tc.exp; !testHelperCmpArr(t, got, exp) {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestValidNodeURI(t *testing.T) {
	testCases := map[string]struct {
		uri string
		exp bool
	}{
		"Empty":          {"", false},
		"No scheme":      {"1.2.3.4", false},
		"HTTP":           {"http://1.2.3.4", true},
		"Blacklisted IP": {"https://0.0.0.0", false},
		"IPv6":           {"https://2001:db8::68", false},
		"Valid":          {"https://1.2.3.4", true},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := validNodeURI(tc.uri), tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	testCases := map[string]struct {
		s   string
		exp bool
	}{
		"Empty":              {"", false},
		"Invalid/One":        {"a", false},
		"Invalid/Two":        {"al", false},
		"Invalid/Three":      {"abc", false},
		"Invalid/odd length": {"112233ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab1", false},
		"Valid/Two":          {"ab", true},
		"Valid/Uppercase":    {"AB", true},
		"Valid/long":         {"112233ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab11", true},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := isHex(tc.s), tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestUniq(t *testing.T) {
	testCases := map[string]struct {
		s   []string
		exp []string
	}{
		"Empty":   {[]string{}, []string{}},
		"One ":    {[]string{"a"}, []string{"a"}},
		"One 2":   {[]string{"a", "a"}, []string{"a"}},
		"Two":     {[]string{"a", "b"}, []string{"a", "b"}},
		"Three":   {[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		"Three 2": {[]string{"a", "b", "b", "c"}, []string{"a", "b", "c"}},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := uniq(tc.s), tc.exp; !testHelperCmpArr(t, got, exp) {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestValidUUID(t *testing.T) {
	testCases := map[string]struct {
		uuid string
		exp  bool
	}{
		"Empty":   {"", false},
		"Invalid": {"6ba7b811-9dad-11d1-80b4-00c04fd430c", false},
		"Valid":   {"6ba7b811-9dad-11d1-80b4-00c04fd430c8", true},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := validUUID(tc.uuid), tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestProcessingHintsNext(t *testing.T) {
	base, err := time.Parse(time.RFC3339, "2018-01-17T03:14:15Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testCases := map[string]struct {
		h   *ProcessingHints
		exp time.Time
	}{
		"Empty": {&ProcessingHints{}, time.Time{}},
		"Cal":   {&ProcessingHints{"cal": base.Add(5 * time.Minute)}, base.Add(5 * time.Minute)},
		"ETH":   {&ProcessingHints{"eth": base.Add(5 * time.Minute)}, base.Add(5 * time.Minute)},
		"BTC":   {&ProcessingHints{"btc": base.Add(5 * time.Minute)}, base.Add(5 * time.Minute)},
		"Cal 2": {&ProcessingHints{"cal": base.Add(5 * time.Minute), "eth": base.Add(15 * time.Minute)}, base.Add(5 * time.Minute)},
		"ETH 2": {&ProcessingHints{"cal": base.Add(-4 * time.Minute), "eth": base.Add(15 * time.Minute)}, base.Add(15 * time.Minute)},
		"None":  {&ProcessingHints{"cal": base.Add(-5 * time.Minute), "eth": base.Add(-4 * time.Minute), "btc": base.Add(-3 * time.Minute)}, time.Time{}},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := tc.h.Next(base), tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func testHelperCmpArr(t *testing.T, a, b []string) bool {
	t.Helper()

	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
