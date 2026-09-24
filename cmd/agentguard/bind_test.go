package main

import "testing"

func TestValidateBind(t *testing.T) {
	for _, c := range []struct {
		bind, key string
		ok        bool
	}{
		{"", "", true},
		{"127.0.0.1", "", true},
		{"localhost", "", true},
		{"0.0.0.0", "", false},
		{"192.168.1.5", "", false},
		{"0.0.0.0", "k", true},
		{"192.168.1.5", "k", true},
	} {
		if err := validateBind(c.bind, c.key); (err == nil) != c.ok {
			t.Errorf("validateBind(%q, key=%q) = %v, want ok=%v", c.bind, c.key, err, c.ok)
		}
	}
}
