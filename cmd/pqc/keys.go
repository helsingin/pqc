package main

import (
	"fmt"

	pqc "github.com/helsingin/pqc"
)

func (a *app) runKeys(args []string) int {
	if len(args) == 0 {
		a.printKeysUsage()
		return 2
	}
	switch args[0] {
	case "create":
		return a.runKeysCreate(args[1:])
	case "rotate":
		return a.runKeysRotate(args[1:])
	case "list":
		return a.runKeysList(args[1:])
	case "show":
		return a.runKeysShow(args[1:])
	case "public":
		return a.runKeysPublic(args[1:])
	case "help", "-h", "--help":
		a.printKeysUsage()
		return 0
	default:
		return a.failUsage(fmt.Errorf("unknown keys command %q", args[0]), a.printKeysUsage)
	}
}

func (a *app) runKeysCreate(args []string) int {
	fs := a.flagSet("pqc keys create")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	id := fs.String("id", "", "key id")
	typ := fs.String("type", "", "key type: ml-kem-768, ml-dsa-65, or ml-dsa-87")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" || *typ == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("keys create requires --id and --type"), a.printKeysUsage)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	algorithm, err := pqc.ParseAlgorithm(*typ)
	if err != nil {
		return a.fail(err)
	}
	meta, err := client.Generate(a.ctx, pqc.GenerateRequest{ID: *id, Algorithm: algorithm})
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, meta)
}

func (a *app) runKeysRotate(args []string) int {
	fs := a.flagSet("pqc keys rotate")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	id := fs.String("id", "", "key id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("keys rotate requires --id"), a.printKeysUsage)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	meta, err := client.Rotate(a.ctx, *id)
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, meta)
}

func (a *app) runKeysList(args []string) int {
	fs := a.flagSet("pqc keys list")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("keys list does not take arguments"), a.printKeysUsage)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	keys, err := client.List(a.ctx)
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, keys)
}

func (a *app) runKeysShow(args []string) int {
	fs := a.flagSet("pqc keys show")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	id := fs.String("id", "", "key id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("keys show requires --id"), a.printKeysUsage)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	meta, err := client.Get(a.ctx, *id)
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, meta)
}

func (a *app) runKeysPublic(args []string) int {
	fs := a.flagSet("pqc keys public")
	var clientOpts clientOptions
	registerClientFlags(fs, &clientOpts)
	id := fs.String("id", "", "key id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" || fs.NArg() != 0 {
		return a.failUsage(fmt.Errorf("keys public requires --id"), a.printKeysUsage)
	}
	client, err := openCommandClient(fs, clientOpts)
	if err != nil {
		return a.fail(err)
	}
	pub, err := client.ExportPublic(a.ctx, *id)
	if err != nil {
		return a.fail(err)
	}
	return writeJSON(a.stdout, a.stderr, pub)
}

func (a *app) printKeysUsage() {
	_, _ = fmt.Fprint(a.stderr, `Usage:
  pqc keys create --type ml-kem-768 --id service-a [manager flags]
  pqc keys create --type ml-dsa-65 --id signer-a [manager flags]
  pqc keys rotate --id KEY [manager flags]
  pqc keys list [manager flags]
  pqc keys show --id KEY [manager flags]
  pqc keys public --id KEY [manager flags]
`)
}
