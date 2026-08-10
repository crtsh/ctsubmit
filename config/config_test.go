package config

import "testing"

func TestParseResponseFormat(t *testing.T) {
	cases := []struct {
		in   string
		want ResponseFormat
	}{
		{"html", RESPONSEFORMAT_HTML},
		{"HTML", RESPONSEFORMAT_HTML},
		{"json", RESPONSEFORMAT_JSON},
		{"JSON", RESPONSEFORMAT_JSON},
		{"xml", -1},
		{"", -1},
	}
	for _, c := range cases {
		if got := ParseResponseFormat(c.in); got != c.want {
			t.Errorf("ParseResponseFormat(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}
