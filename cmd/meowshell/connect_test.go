package main

import "testing"

func TestShellQuoteJoin(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"echo", "hi"}, "'echo' 'hi'"},
		{[]string{"echo", "hello world"}, "'echo' 'hello world'"},
		{[]string{"sh", "-c", "exit 42"}, "'sh' '-c' 'exit 42'"},
		{[]string{"echo", "it's"}, `'echo' 'it'"'"'s'`},
	} {
		got := shellQuoteJoin(tt.args)
		if got != tt.want {
			t.Errorf("shellQuoteJoin(%v) = %q; want %q", tt.args, got, tt.want)
		}
	}
}
