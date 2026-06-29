package main

import (
	"fmt"
	"time"

	pqc "github.com/helsingin/pqc"
)

func (a *app) runReadiness(args []string) int {
	if len(args) == 0 {
		a.printReadinessUsage()
		return 2
	}
	switch args[0] {
	case "scan":
		return a.runReadinessScan(args[1:])
	case "help", "-h", "--help":
		a.printReadinessUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown readiness command %q", args[0]), a.printReadinessUsage)
	}
}

func (a *app) runReadinessScan(args []string) int {
	fs := a.flagSet("pqc readiness scan")
	var clientOpts clientOptions
	var targetOpts inspectTargetOptions
	registerClientAccessFlags(fs, &clientOpts)
	registerTargetFlags(fs, &targetOpts)
	policy := fs.String("policy", pqc.TLSReadinessPolicyPublicWeb2029, "readiness policy to apply to TLS targets")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("readiness scan does not take positional arguments"), a.printReadinessUsage)
	}
	var client commandClient
	if inventoryNeedsManager(fs, clientOpts, len(targetOpts.Targets)) {
		var err error
		client, err = openCommandClient(fs, clientOpts)
		if err != nil {
			return a.fail(err)
		}
	}
	report, err := buildInventoryReport(a.ctx, client, targetOpts, *policy)
	if err != nil {
		return a.fail(err)
	}
	scan := pqc.BuildReadinessScan(report, time.Now().UTC())
	return writeJSON(a.stdout, a.stderr, scan)
}

func (a *app) printReadinessUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc readiness scan [--store DIR] [--target HOST:PORT] [--policy public-web-2029] [manager access flags]

Target inspection flags:
  --target HOST:PORT                  TLS endpoint to inspect; repeatable
  --target-server-name NAME           override target TLS server name
  --target-ca FILE                    CA PEM file for target TLS verification
  --target-insecure-skip-verify       skip target TLS certificate verification
  --target-pqc                        prefer hybrid PQC TLS key exchange
  --target-timeout DURATION           target inspection timeout
`)
}
