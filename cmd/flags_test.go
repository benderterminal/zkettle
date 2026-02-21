package cmd

import (
	"reflect"
	"testing"
)

func TestReorderFlagsBoolean(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "json flag does not consume positional",
			args: []string{"--json", "positional"},
			want: []string{"--json", "positional"},
		},
		{
			name: "positional before json flag",
			args: []string{"positional", "--json"},
			want: []string{"--json", "positional"},
		},
		{
			name: "value flag with boolean flag and positional",
			args: []string{"--views", "5", "--json", "positional"},
			want: []string{"--views", "5", "--json", "positional"},
		},
		{
			name: "short quiet flag does not consume positional",
			args: []string{"-q", "positional"},
			want: []string{"-q", "positional"},
		},
		{
			name: "multiple value flags",
			args: []string{"--server", "http://localhost:3000", "--json"},
			want: []string{"--server", "http://localhost:3000", "--json"},
		},
		{
			name: "tunnel flag does not consume positional",
			args: []string{"--tunnel", "positional"},
			want: []string{"--tunnel", "positional"},
		},
		{
			name: "trust-proxy flag does not consume positional",
			args: []string{"--trust-proxy", "positional"},
			want: []string{"--trust-proxy", "positional"},
		},
		{
			name: "quiet flag does not consume positional",
			args: []string{"--quiet", "positional"},
			want: []string{"--quiet", "positional"},
		},
		{
			name: "no flags",
			args: []string{"positional1", "positional2"},
			want: []string{"positional1", "positional2"},
		},
		{
			name: "all flags no positional",
			args: []string{"--views", "5", "--minutes", "60"},
			want: []string{"--views", "5", "--minutes", "60"},
		},
		{
			name: "empty args",
			args: []string{},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reorderFlags(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reorderFlags(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
