package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCheckedFrameLengthRejectsOversizedPayloadWithoutAllocation(t *testing.T) {
	if _, err := checkedFrameLength(maxFrameLength - frameHeaderLength + 1); err == nil {
		t.Fatal("checkedFrameLength accepted an oversized payload")
	}
}

func TestCheckedFrameLengthAcceptsMaximumPayload(t *testing.T) {
	got, err := checkedFrameLength(maxFrameLength - frameHeaderLength)
	if err != nil {
		t.Fatalf("checkedFrameLength rejected the maximum payload: %v", err)
	}
	if got != maxFrameLength {
		t.Fatalf("checkedFrameLength = %d; want %d", got, maxFrameLength)
	}
}

func TestReadFrameRejectsLengthShorterThanHeaderBeforeAllocation(t *testing.T) {
	var buf bytes.Buffer
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], frameHeaderLength-1)
	buf.Write(length[:])

	_, err := readFrame(&buf)
	if err == nil || !strings.Contains(err.Error(), "shorter than the header") {
		t.Fatalf("readFrame error = %v; want short-header error", err)
	}
}

func TestReadFrameRejectsOversizedLengthBeforeAllocation(t *testing.T) {
	var buf bytes.Buffer
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], maxFrameLength+1)
	buf.Write(length[:])

	_, err := readFrame(&buf)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readFrame error = %v; want oversized-frame error", err)
	}
}
