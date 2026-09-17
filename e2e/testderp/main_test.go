package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestAdmissionControllerAllowsRegisteredNodeAndRejectsUnknownNode(t *testing.T) {
	allowedPrivate := key.NewNode()
	allowedPublic := allowedPrivate.Public()
	deniedPrivate := key.NewNode()

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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{
			Allow: request.NodePublic == allowedPublic,
		})
	}))
	defer admission.Close()

	relay := derpserver.New(key.NewNode(), t.Logf)
	configureAdmission(relay, admission.URL, false)
	defer relay.Close()

	relayHTTP := httptest.NewServer(derpserver.Handler(relay))
	defer relayHTTP.Close()

	allowed := newDERPClient(t, allowedPrivate, relayHTTP.URL)
	defer allowed.Close()
	if message, err := connectAndRecvFirst(t, allowed); err != nil {
		t.Fatalf("allowed node handshake: %v", err)
	} else if _, ok := message.(derp.ServerInfoMessage); !ok {
		t.Fatalf("allowed node first message type = %T, want derp.ServerInfoMessage", message)
	}

	denied := newDERPClient(t, deniedPrivate, relayHTTP.URL)
	defer denied.Close()
	if _, err := connectAndRecvFirst(t, denied); err == nil {
		t.Fatal("unknown node unexpectedly completed the admission-protected DERP handshake")
	}
}

func TestAdmissionControllerFailureFailsClosed(t *testing.T) {
	deadController := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	controllerURL := deadController.URL
	deadController.Close()

	relay := derpserver.New(key.NewNode(), t.Logf)
	configureAdmission(relay, controllerURL, false)
	defer relay.Close()

	relayHTTP := httptest.NewServer(derpserver.Handler(relay))
	defer relayHTTP.Close()

	client := newDERPClient(t, key.NewNode(), relayHTTP.URL)
	defer client.Close()
	if _, err := connectAndRecvFirst(t, client); err == nil {
		t.Fatal("node unexpectedly completed the DERP handshake while fail-closed admission controller was unavailable")
	}
}

func newDERPClient(t *testing.T, private key.NodePrivate, serverURL string) *derphttp.Client {
	t.Helper()
	client, err := derphttp.NewClient(private, serverURL, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func connectAndRecvFirst(t *testing.T, client *derphttp.Client) (derp.ReceivedMessage, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	return client.Recv()
}
