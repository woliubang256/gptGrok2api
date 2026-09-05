package httpapi

import "testing"

func TestNormalizeGrokImageSize(t *testing.T) {
	cases := map[string]string{
		"":            "1024x1024",
		"auto":        "1024x1024",
		"AUTO":        "1024x1024",
		"  1024x1024": "1024x1024",
		"1024x1792":   "1024x1792",
		"16:9":        "16:9",
	}
	for input, want := range cases {
		if got := normalizeGrokImageSize(input); got != want {
			t.Errorf("normalizeGrokImageSize(%q) = %q, want %q", input, got, want)
		}
	}
}
