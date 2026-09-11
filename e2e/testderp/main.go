// Command testderp runs a single-node DERP relay bound to 127.0.0.1 and
// serves a matching tailcfg.DERPMap as JSON over plain HTTP, so CI jobs can
// point TAILCAT_DERPMAP_URL at it instead of the public Tailscale relay
// infrastructure. tailcat and meowshell need no code changes for this: both
// already read TAILCAT_DERPMAP_URL as a fallback when no --derpmap-url flag
// is given, and meowshell execs tailcat with its own environment inherited,
// so setting the variable once in a CI step's environment covers every
// meowshell/tailcat process that step launches.
//
// On ready, it prints one line to stdout:
//
//	TAILCAT_DERPMAP_URL=http://127.0.0.1:PORT/derpmap.json
//
// and then blocks until killed (SIGINT/SIGTERM for a clean shutdown).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func main() {
	statusFile := flag.String("status-file", "", "also write the TAILCAT_DERPMAP_URL= line to this file once ready")
	flag.Parse()
	if err := run(*statusFile); err != nil {
		fmt.Fprintf(os.Stderr, "testderp: %v\n", err)
		os.Exit(1)
	}
}

func run(statusFile string) error {
	d := derpserver.New(key.NewNode(), log.Printf)
	defer d.Close()

	derpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listening for DERP: %w", err)
	}
	derpSrv := httptest.NewUnstartedServer(derpserver.Handler(d))
	derpSrv.Listener.Close()
	derpSrv.Listener = derpLn
	derpSrv.StartTLS()
	defer derpSrv.Close()

	derpPort := derpLn.Addr().(*net.TCPAddr).Port
	derpMap := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			900: {
				RegionID:   900,
				RegionCode: "ci",
				RegionName: "local CI relay",
				Nodes: []*tailcfg.DERPNode{{
					Name:             "900a",
					RegionID:         900,
					HostName:         "127.0.0.1",
					IPv4:             "127.0.0.1",
					IPv6:             "none",
					DERPPort:         derpPort,
					STUNPort:         -1,
					InsecureForTests: true,
				}},
			},
		},
	}
	mapJSON, err := json.Marshal(derpMap)
	if err != nil {
		return fmt.Errorf("marshaling DERP map: %w", err)
	}

	mapLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listening for the DERP map endpoint: %w", err)
	}
	mapMux := http.NewServeMux()
	mapMux.HandleFunc("/derpmap.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mapJSON)
	})
	mapSrv := &http.Server{Handler: mapMux}
	go mapSrv.Serve(mapLn)
	defer mapSrv.Close()

	mapURL := fmt.Sprintf("http://%s/derpmap.json", mapLn.Addr())
	statusLine := fmt.Sprintf("TAILCAT_DERPMAP_URL=%s\n", mapURL)
	fmt.Print(statusLine)
	if statusFile != "" {
		if err := os.WriteFile(statusFile, []byte(statusLine), 0o644); err != nil {
			return fmt.Errorf("writing status file: %w", err)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return nil
}
