package client

import (
	"strings"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{
			name: "commercial https",
			in:   "https://cloud.tenable.com",
			want: "https://cloud.tenable.com",
		},
		{
			name: "fedramp https",
			in:   "https://fedcloud.tenable.com",
			want: "https://fedcloud.tenable.com",
		},
		{
			name: "http mock",
			in:   "http://localhost:8765",
			want: "http://localhost:8765",
		},
		{
			name: "trims trailing slash",
			in:   "https://cloud.tenable.com/",
			want: "https://cloud.tenable.com",
		},
		{
			name: "trims whitespace and trailing slash",
			in:   "  https://fedcloud.tenable.com/  ",
			want: "https://fedcloud.tenable.com",
		},
		{
			name:    "empty",
			in:      "",
			wantErr: "base URL is empty",
		},
		{
			name:    "whitespace only",
			in:      "   ",
			wantErr: "base URL is empty",
		},
		{
			name:    "scheme-less host",
			in:      "cloud.tenable.com",
			wantErr: "must include an http:// or https:// scheme",
		},
		{
			name:    "https with no host",
			in:      "https://",
			wantErr: "missing host",
		},
		{
			name:    "unsupported scheme",
			in:      "ftp://cloud.tenable.com",
			wantErr: "must include an http:// or https:// scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeBaseURL(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("normalizeBaseURL(%q) error = nil, want %q", tt.in, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("normalizeBaseURL(%q) error = %v, want substring %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeBaseURL(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeBaseURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
