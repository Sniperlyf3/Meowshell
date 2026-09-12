//go:build unix

package main

import (
	"os"
	"strconv"
	"testing"
)

func TestConsumeManagedHostPIDRemovesInheritedMarker(t *testing.T) {
	old, had := os.LookupEnv(managedParentPIDEnv)
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(managedParentPIDEnv, old)
		} else {
			_ = os.Unsetenv(managedParentPIDEnv)
		}
	})

	_ = os.Setenv(managedParentPIDEnv, "4242")
	if got := consumeManagedHostPID(); got != 4242 {
		t.Fatalf("consumeManagedHostPID() = %d, want 4242", got)
	}
	if _, ok := os.LookupEnv(managedParentPIDEnv); ok {
		t.Fatal("managed-parent marker remained in process environment for descendants")
	}
}

func TestManagedExecMarkerCanBeReinsertedExplicitly(t *testing.T) {
	env := setEnv([]string{"KEEP=yes"}, [][2]string{
		{managedParentPIDEnv, strconv.Itoa(4242)},
	})
	want := managedParentPIDEnv + "=4242"
	found := false
	for _, entry := range env {
		if entry == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("reinserted exec environment %v does not contain %q", env, want)
	}
}
