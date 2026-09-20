// aip-spiffe-workload — a workload that asks SPIRE who it is, and prints the
// answer as JSON for AIP to compare against.
//
// # Why this exists as a real program rather than a shell call
//
// The SPIRE Workload API attests *the process on the other end of the socket*.
// If the caller were a shell or SPIRE's own CLI, the identity under test would
// be the shell's or SPIRE's, not a workload we control and can register by its
// binary's SHA-256. This program is therefore the workload: its own executable
// is what SPIRE measures, and the entry it matches is selected on that digest.
//
// # What it deliberately does NOT do
//
// It does not compute or assert its own binary's hash as evidence. A process
// reporting its own measurement proves nothing. The evidence is that SPIRE
// *issued an SVID for an entry selected on unix:sha256*, which means SPIRE
// measured that digest independently; and, separately, that AIP's probe
// measured the same process from the kernel. Those two are the comparison.
//
// It uses SPIRE's own client library (go-spiffe) rather than parsing the
// Workload API or X.509 ourselves, for the same reason the MCP gateway calls
// the real signer: a disagreement must never be blamable on our parser.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type output struct {
	Pid          int      `json:"pid"`
	ExePath      string   `json:"exe_path"`
	SpiffeID     string   `json:"spiffe_id"`
	TrustDomain  string   `json:"trust_domain"`
	Serial       string   `json:"serial"`
	NotBeforeMs  int64    `json:"not_before_ms"`
	NotAfterMs   int64    `json:"not_after_ms"`
	SvidChainPem string   `json:"svid_chain_pem"`
	BundlePem    string   `json:"bundle_pem"`
	DNSNames     []string `json:"dns_names"`
	ObservedAtMs int64    `json:"observed_at_ms"`
}

func encodeCerts(certs []*x509.Certificate) string {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return string(out)
}

func main() {
	socket := flag.String("socket", "", "Workload API socket path (required)")
	hold := flag.Duration("hold", 0, "stay alive this long after fetching, so an external observer can see the process")
	flag.Parse()
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "-socket is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+*socket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "workload api: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	svids, err := client.FetchX509SVIDs(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch svid: %v\n", err)
		os.Exit(1)
	}
	if len(svids) == 0 {
		// No SVID means no registration entry matched this process. That is a
		// real outcome, not an error to paper over: it is SPIRE declining to
		// name this workload.
		fmt.Fprintln(os.Stderr, "SPIRE issued no SVID: no registration entry matched this process")
		os.Exit(3)
	}
	svid := svids[0]

	bundles, err := client.FetchX509Bundles(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch bundles: %v\n", err)
		os.Exit(1)
	}
	bundlePem := ""
	if b, err := bundles.GetX509BundleForTrustDomain(svid.ID.TrustDomain()); err == nil {
		bundlePem = encodeCerts(b.X509Authorities())
	}

	exe, _ := os.Executable()
	leaf := svid.Certificates[0]
	o := output{
		Pid:          os.Getpid(),
		ExePath:      exe,
		SpiffeID:     svid.ID.String(),
		TrustDomain:  svid.ID.TrustDomain().String(),
		Serial:       leaf.SerialNumber.String(),
		NotBeforeMs:  leaf.NotBefore.UnixMilli(),
		NotAfterMs:   leaf.NotAfter.UnixMilli(),
		SvidChainPem: encodeCerts(svid.Certificates),
		BundlePem:    bundlePem,
		DNSNames:     leaf.DNSNames,
		ObservedAtMs: time.Now().UnixMilli(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&o); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
	if *hold > 0 {
		time.Sleep(*hold)
	}
}
