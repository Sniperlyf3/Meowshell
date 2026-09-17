package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestAdmissionControllerAllowsRegisteredNodeAndRejectsUnknownNode(t *testing.T) {
	allowed := key.NewNode()
	var sawAllowed bool
	admission := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var request tailcfg.DERPAdmitClientRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		allow := request.NodePublic == allowed.Public()
		if allow {
			sawAllowed = true
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: allow}); err != nil {
			t.Errorf("encoding admission response: %v", err)
		}
	}))
	defer admission.Close()

	relay, relayURL := startAdmissionTestRelay(t, admission.URL, false)
	defer relay.Close()

	allowedClient := newDERPClient(t, allowed, relayURL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := allowedClient.Connect(ctx); err != nil {
		t.Fatalf("allowed client Connect: %v", err)
	}
	allowedClient.Close()
	if !sawAllowed {
		t.Fatal("admission controller did not observe the allowed node")
	}

	deniedClient := newDERPClient(t, key.NewNode(), relayURL)
	deniedCtx, deniedCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer deniedCancel()
	if err := deniedClient.Connect(deniedCtx); err == nil {
		deniedClient.Close()
		t.Fatal("unknown client connected despite admission denial")
	}
}

func TestAdmissionControllerFailureFailsClosed(t *testing.T) {
	admission := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	admissionURL := admission.URL
	admission.Close()

	relay, relayURL := startAdmissionTestRelay(t, admissionURL, false)
	defer relay.Close()

	client := newDERPClient(t, key.NewNode(), relayURL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err == nil {
		client.Close()
		t.Fatal("client connected while fail-closed admission controller was unreachable")
	}
}

func startAdmissionTestRelay(t *testing.T, admissionURL string, failOpen bool) (*derpserver.Server, string) {
	t.Helper()
	relay := derpserver.New(key.NewNode(), t.Logf)
	configureAdmission(relay, admissionURL, failOpen)
	server := httptest.NewServer(derpserver.Handler(relay))
	t.Cleanup(server.Close)
	return relay, server.URL
}

func newDERPClient(t *testing.T, privateKey key.NodePrivate, serverURL string) *derphttp.Client {
	t.Helper()
	client, err := derphttp.NewClient(privateKey, serverURL, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("derphttp.NewClient: %v", err)
	}
	return client
}
