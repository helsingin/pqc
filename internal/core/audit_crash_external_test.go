package core_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/helsingin/pqc"
	"github.com/helsingin/pqc/store/file"
)

func TestCrashAfterStoreCommitHelper(t *testing.T) {
	directory := os.Getenv("PQC_TEST_COMMIT_PATH")
	if directory == "" {
		t.Skip("subprocess helper")
	}
	store, err := file.New(directory)
	if err != nil {
		t.Fatal(err)
	}
	manager := pqc.NewManager(store, pqc.WithAuditor(pqc.AuditorFunc(func(context.Context, pqc.AuditEvent) error { os.Exit(23); return nil })))
	if os.Getenv("PQC_TEST_COMMIT_MODE") == "rotate" {
		_, _ = manager.Rotate(t.Context(), "operation")
	} else {
		_, _ = manager.Generate(t.Context(), pqc.GenerateRequest{ID: "operation", Algorithm: pqc.AlgorithmMLDSA65})
	}
	t.Fatal("helper did not terminate after commit")
}

func TestCrashBeforeAuditReceiptRequiresReconciliation(t *testing.T) {
	for _, mode := range []string{"generate", "rotate"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			store, err := file.New(directory)
			if err != nil {
				t.Fatal(err)
			}
			manager := pqc.NewManager(store)
			expected := 1
			if mode == "rotate" {
				if _, err := manager.Generate(t.Context(), pqc.GenerateRequest{ID: "operation", Algorithm: pqc.AlgorithmMLDSA65}); err != nil {
					t.Fatal(err)
				}
				expected = 2
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashAfterStoreCommitHelper$")
			command.Env = append(os.Environ(), "PQC_TEST_COMMIT_PATH="+directory, "PQC_TEST_COMMIT_MODE="+mode)
			var exited *exec.ExitError
			if err := command.Run(); !errors.As(err, &exited) || exited.ExitCode() != 23 {
				t.Fatalf("unexpected helper exit: %v", err)
			}
			// The child returned no receipt. Query committed state instead of repeating
			// rotation (which would create another key version).
			reopened, err := file.New(directory)
			if err != nil {
				t.Fatal(err)
			}
			result, err := pqc.NewManager(reopened).Get(t.Context(), "operation")
			if err != nil || result.Version != expected {
				t.Fatalf("reconciled state: %+v %v", result, err)
			}
		})
	}
}
