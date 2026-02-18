package tunnel

import (
	"testing"
)

func TestTunnelURLRegex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard cloudflared output",
			input: `2024-01-15T10:30:00Z INF +--------------------------------------------------------------------------------------------+`,
			want:  "",
		},
		{
			name:  "url line",
			input: `2024-01-15T10:30:00Z INF |  https://cold-penguin-abc123.trycloudflare.com                                        |`,
			want:  "https://cold-penguin-abc123.trycloudflare.com",
		},
		{
			name:  "url with numbers",
			input: `INF https://test-42-tunnel99.trycloudflare.com`,
			want:  "https://test-42-tunnel99.trycloudflare.com",
		},
		{
			name:  "no match plain text",
			input: `Starting tunnel...`,
			want:  "",
		},
		{
			name:  "connector registered line",
			input: `2024-01-15T10:30:00Z INF Registered tunnel connection connIndex=0`,
			want:  "",
		},
		{
			name:  "url with single word subdomain",
			input: `https://abcdef.trycloudflare.com`,
			want:  "https://abcdef.trycloudflare.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tunnelURLRe.FindString(tt.input)
			if got != tt.want {
				t.Errorf("tunnelURLRe.FindString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
