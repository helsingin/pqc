//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package core

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAuditProcessHelper(t *testing.T) {
	path := os.Getenv("PQC_TEST_AUDIT_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	switch os.Getenv("PQC_TEST_AUDIT_MODE") {
	case "crash":
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(`{"event_id":"interrupted`); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		os.Exit(23) // Simulate loss of the process before a complete record exists.
	case "record":
		auditor, err := NewFileAuditor(path)
		if err != nil {
			t.Fatal(err)
		}
		event := AuditEvent{ID: os.Getenv("PQC_TEST_AUDIT_ID"), Operation: "sign", Time: time.Unix(1800000000, 0).UTC(), Outcome: AuditSucceeded, Success: true}
		if err := auditor.Record(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown helper mode")
	}
}

func TestAuditConcurrentProcessesAndInterruptedAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	auditor, err := NewFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	command := func(mode, id string) *exec.Cmd {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAuditProcessHelper$")
		cmd.Env = append(os.Environ(), "PQC_TEST_AUDIT_PATH="+path, "PQC_TEST_AUDIT_MODE="+mode, "PQC_TEST_AUDIT_ID="+id)
		return cmd
	}
	var workers sync.WaitGroup
	for _, id := range []string{"shared", "shared", "shared", "a", "b", "c"} {
		workers.Go(func() {
			if out, err := command("record", id).CombinedOutput(); err != nil {
				t.Errorf("writer: %v %s", err, out)
			}
		})
	}
	workers.Wait()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(before, []byte("\n")) != 4 {
		t.Fatalf("lost/duplicated records: %s", before)
	}
	if err := command("crash", "").Run(); err == nil {
		t.Fatal("crash helper did not exit")
	}
	event := AuditEvent{ID: "shared", Operation: "sign", Time: time.Unix(1800000000, 0).UTC(), Outcome: AuditSucceeded, Success: true}
	if err := auditor.Record(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("crash recovery changed committed events: %v", err)
	}
}

func TestAuditLockCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	auditor, err := NewFileAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	held, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := lockAudit(t.Context(), held); err != nil {
		t.Fatal(err)
	}
	defer unlockAudit(held)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	event := AuditEvent{ID: "blocked", Operation: "sign", Time: time.Unix(1800000000, 0).UTC(), Outcome: AuditSucceeded, Success: true}
	if err := auditor.Record(ctx, event); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock ignored cancellation: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) != 0 {
		t.Fatalf("cancelled write changed file: %v", err)
	}
}
