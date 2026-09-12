//go:build unix

package main

import (
	"strconv"
	"testing"
)

func TestShouldArmParentDeathSignal(t *testing.T) {
	const parent = 4242

	if shouldArmParentDeathSignal(nil, parent) != true {
		t.Fatal("standalone launch must retain PDEATHSIG")
	}
	if shouldArmParentDeathSignal(
		[]string{managedParentPIDEnv + "=" + strconv.Itoa(parent)}, parent) {
		t.Fatal("managed launch with matching host PID must not arm thread-coupled PDEATHSIG")
	}
	if !shouldArmParentDeathSignal(
		[]string{managedParentPIDEnv + "=9999"}, parent) {
		t.Fatal("mismatched marker must not disable PDEATHSIG")
	}
	if !shouldArmParentDeathSignal(
		[]string{managedParentPIDEnv + "=not-a-pid"}, parent) {
		t.Fatal("invalid marker must fail closed and retain PDEATHSIG")
	}
}
