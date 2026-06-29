package main

import (
	"fmt"
)

func (a *app) runInventory(args []string) int {
	if len(args) == 0 {
		a.printInventoryUsage()
		return 2
	}
	switch args[0] {
	case "scan":
		return a.runInventoryScan(args[1:])
	case "help", "-h", "--help":
		a.printInventoryUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown inventory command %q", args[0]), a.printInventoryUsage)
	}
}

func (a *app) runInventoryScan(args []string) int {
	fs := a.flagSet("pqc inventory scan")
	var clientOpts clientOptions
	var targetOpts inspectTargetOptions
	registerClientAccessFlags(fs, &clientOpts)
	registerTargetFlags(fs, &targetOpts)
	policy := fs.String("policy", "", "readiness policy to apply to TLS targets, e.g. public-web-2029")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("inventory scan does not take positional arguments"), a.printInventoryUsage)
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
	return writeJSON(a.stdout, a.stderr, report)
}

func (a *app) printInventoryUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc inventory scan [--target HOST:PORT] [--policy public-web-2029] [manager access flags]

Target inspection flags:
  --target HOST:PORT                  TLS endpoint to inspect; repeatable
  --target-server-name NAME           override target TLS server name
  --target-ca FILE                    CA PEM file for target TLS verification
  --target-insecure-skip-verify       skip target TLS certificate verification
  --target-pqc                        prefer hybrid PQC TLS key exchange
  --target-timeout DURATION           target inspection timeout
  --policy POLICY                     attach readiness policy output to TLS targets
`)
}
