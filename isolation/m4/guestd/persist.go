// persist.go - what guestd keeps on disk so that a guestd RESTART does not end every guest (finding F7), and so that
// a failed start leaves its reason behind (finding F9).
//
// F7. Guests are SNP VMs in their own user units and outlive this process. A record of each running instance is
// written into its workdir (instance.json) when it becomes running. At boot, each record whose unit is still active is
// considered for ADOPTION: its forwarder is started again and the guest is VERIFIED again through the same judge a
// launch uses, against the recorded measurement, AppID and HOST_DATA; it is adopted only if that passes AND the key
// its handshake presents is the recorded one (the same guest, not a replacement). Everything else - a dead unit, a
// missing or unreadable record, a failed verification, a different key - is stopped and scrubbed exactly as before.
// The record is the host's own bookkeeping on the host's disk, which the design treats as untrusted: it only picks
// what to re-verify; the verification decides. An adopted instance's lease is the manager's usual dead-man lease,
// inert until the supervisor's next heartbeat.
//
// F9. A failed start used to scrub its workdir, serial console included, so its reason was lost. Now the tail of the
// serial console and the build/launch/verify logs are kept under <root>/failed/<id>/ (bounded, newest 32), and
// GET /vms/<id>/logs serves the serial tail of a running or failed instance in the supervisor's logs shape.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"enclave.host/isolation/contract"
)

const (
	recordFile     = "instance.json"
	keepFailed     = 32
	failedLogBytes = 64 << 10
)

type instanceRecord struct {
	GPUCardBytes                                                                            int64
	InferenceModel                                                                          string
	ID, Name, AppID, Measurement, RecordSha256, HostData, TransportKeySha256, Unit, Verdict string
	CID                                                                                     uint32
	Vcpus, MemMiB, CPUPct                                                                   int
	Release                                                                                 bool // a release guest: egress stays admitted after adoption (release.go)
	// Legacy: built from the legacy tree (-legacy-isolation). Adoption re-verifies against the RECORDED measurement, so
	// it needs neither tree; this keeps the instance's public view (legacyImage) true across a guestd restart.
	DirectBootstrap bool
	Legacy          bool
	// Releases: the release(s) of the tree that built the guest (server.go treeReleases), named to the judge again on
	// adoption. Absent (null) in a record an earlier guestd wrote: adoption then names -unrecorded-releases. The record
	// only picks what the judge is told; the judge's own table decides what a release may state.
	RuntimeID string
	Releases  []string
	Created   time.Time
}

// persistRunning writes the record of an instance that just became running. Best effort: without it the instance
// is simply not adoptable after a guestd restart, which is today's behaviour.
func (s *server) persistRunning(v *vm) {
	s.mu.Lock()
	rec := instanceRecord{GPUCardBytes: v.GPUCardBytes, InferenceModel: v.InferenceModel, ID: v.ID, Name: v.Name, AppID: v.AppID, Measurement: v.Measurement, RecordSha256: v.RecordSha256,
		HostData: v.HostData, TransportKeySha256: v.TransportKeySha256, Unit: v.unit, Verdict: v.Verdict, CID: v.cid,
		Vcpus: v.Vcpus, MemMiB: v.MemMiB, CPUPct: v.CPUPct, Created: v.Created, Release: v.release, Legacy: v.legacy, DirectBootstrap: v.directBootstrap,
		Releases: append([]string{}, v.releases...), RuntimeID: s.vmRuntime(v)}
	dir := v.workdir
	s.mu.Unlock()
	b, _ := json.Marshal(rec)
	tmp := filepath.Join(dir, recordFile+".tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, filepath.Join(dir, recordFile))
	}
}

// adoptOnBoot runs before guestd serves: it adopts what verifies and returns the units to keep, and the ids adopted
// and dropped, for the log. The caller then sweeps every other guest unit and scrubs every other workdir.
func (s *server) adoptOnBoot(ctx context.Context) (keep map[string]bool, adopted, dropped []string) {
	keep = map[string]bool{}
	dirs, _ := filepath.Glob(filepath.Join(s.Root, s.idPrefix()+"*"))
	for _, dir := range dirs {
		id := filepath.Base(dir)
		why := s.adoptOne(ctx, dir)
		if why == "" {
			s.mu.Lock()
			keep[s.vms[id].unit] = true
			s.mu.Unlock()
			adopted = append(adopted, id)
			continue
		}
		dropped = append(dropped, id+": "+why)
		// not adopted: the guest (if any) ends and nothing of it stays, exactly as a boot sweep always did
		var rec instanceRecord
		if b, err := os.ReadFile(filepath.Join(dir, recordFile)); err == nil && json.Unmarshal(b, &rec) == nil && rec.Unit != "" {
			_ = s.L.Stop(id, dir)
		}
		_ = os.RemoveAll(dir)
	}
	return keep, adopted, dropped
}

func (s *server) adoptOne(ctx context.Context, dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, recordFile))
	if err != nil {
		return "no instance record (it never became running, or predates adoption)"
	}
	var rec instanceRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return "unreadable instance record"
	}
	if rec.ID != filepath.Base(dir) || !isHex(rec.TransportKeySha256, 32) || !isHex(rec.AppID, 32) || rec.Unit == "" || rec.CID == 0 {
		return "incomplete instance record"
	}
	if s.ShieldEnabled || rec.GPUCardBytes != 0 || rec.InferenceModel != "" {
		raw, readErr := os.ReadFile(filepath.Join(dir, "app.bundle"))
		if readErr != nil {
			return "missing measured bundle"
		}
		manifest, _, parseErr := contract.Parse(raw)
		if parseErr != nil {
			return "invalid measured bundle"
		}
		appID := contract.AppID(raw)
		if fmt.Sprintf("%x", appID) != rec.AppID {
			return "bundle identity changed"
		}
		if rec.GPUCardBytes != manifest.Inference.CardBytes() {
			return "GPU reservation differs from measured bundle"
		}
		if (manifest.Inference == nil && rec.InferenceModel != "") || (manifest.Inference != nil && rec.InferenceModel != manifest.Inference.Model) {
			return "inference model differs from measured bundle"
		}
	}
	if !s.L.Alive(rec.Unit) {
		return "its unit is no longer active"
	}
	port, stop, err := s.L.Forward(ctx, rec.CID, dir)
	if err != nil {
		return "no forwarder: " + err.Error()
	}
	rel := rec.Releases
	if rel == nil {
		rel = append([]string{}, s.UnrecordedReleases...) // an earlier guestd's record: the releases the operator names for those
	}
	verdict, keySha, err := s.L.Verify(ctx, port, rec.Measurement, rec.AppID, rec.HostData, dir, rel)
	if err != nil || keySha != rec.TransportKeySha256 {
		stop()
		if err != nil {
			return "it does not verify again: " + err.Error()
		}
		return fmt.Sprintf("it presents key %.16s..., not the recorded %.16s... (not the same guest)", keySha, rec.TransportKeySha256)
	}
	rid := s.RuntimeID
	if resolver, ok := s.L.(interface {
		RuntimeForReleases([]string) (string, error)
	}); ok {
		rid, err = resolver.RuntimeForReleases(rel)
		if err != nil {
			stop()
			return "runtime pin: " + err.Error()
		}
	}
	if rec.RuntimeID != "" && rec.RuntimeID != rid {
		stop()
		return "recorded runtime changed"
	}
	lc := contract.NewLifecycle(contract.Starting)
	lc.FinishStart()
	v := &vm{GPUCardBytes: rec.GPUCardBytes, InferenceModel: rec.InferenceModel, ID: rec.ID, Name: rec.Name, AppID: rec.AppID, Measurement: rec.Measurement, Status: "running", Verdict: verdict,
		RecordSha256: rec.RecordSha256, RuntimeID: rid, TransportKeySha256: keySha, HostData: rec.HostData, HostPort: port,
		Vcpus: rec.Vcpus, MemMiB: rec.MemMiB, CPUPct: rec.CPUPct, Created: rec.Created, unit: rec.Unit, cid: rec.CID,
		workdir: dir, stopFwd: stop, lc: lc, leaseUntil: s.Now().Add(s.LeaseTTL), release: rec.Release, legacy: rec.Legacy, directBootstrap: rec.DirectBootstrap, releases: rel}
	s.mu.Lock()
	for _, o := range s.vms {
		if o.Name == v.Name {
			s.mu.Unlock()
			stop()
			return "another instance already holds its name"
		}
	}
	s.vms[v.ID] = v
	s.mu.Unlock()
	return ""
}

// preserveFailed keeps the reason a start failed before its workdir is scrubbed.
func (s *server) preserveFailed(v *vm) {
	s.mu.Lock()
	id, dir, why := v.ID, v.workdir, v.Error
	s.mu.Unlock()
	if dir == "" {
		return
	}
	out := filepath.Join(s.Root, "failed", id)
	if os.MkdirAll(out, 0o700) != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(out, "error.txt"), []byte(why+"\n"), 0o600)
	for _, f := range []string{id + ".serial", "build.txt", id + ".host", "verify.txt"} {
		if b := tailFile(filepath.Join(dir, f), failedLogBytes); b != nil {
			_ = os.WriteFile(filepath.Join(out, f), b, 0o600)
		}
	}
	pruneFailed(filepath.Join(s.Root, "failed"), keepFailed)
}

func tailFile(p string, max int64) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if st.Size() > max {
		_, _ = f.Seek(st.Size()-max, io.SeekStart)
	}
	b, _ := io.ReadAll(io.LimitReader(f, max))
	return b
}

func pruneFailed(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) <= keep {
		return
	}
	type e struct {
		name string
		at   time.Time
	}
	var all []e
	for _, d := range ents {
		if info, err := d.Info(); err == nil {
			all = append(all, e{d.Name(), info.ModTime()})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.After(all[j].at) })
	for _, x := range all[keep:] {
		_ = os.RemoveAll(filepath.Join(dir, x.name))
	}
}

// logs answers GET /vms/<id>/logs?tail=N in the supervisor's shape: {status, error?, lines}. A running instance's
// serial console, or what a failed start preserved. The serial console is the host's file in any case.
func (s *server) logs(v *vm, tail int) (map[string]any, error) {
	s.mu.Lock()
	id, dir, status, why := v.ID, v.workdir, v.Status, v.Error
	s.mu.Unlock()
	if tail <= 0 || tail > 2000 {
		tail = 200
	}
	p := filepath.Join(dir, id+".serial")
	if status == "failed" {
		p = filepath.Join(s.Root, "failed", id, id+".serial")
	}
	b := tailFile(p, failedLogBytes)
	if b == nil {
		return nil, errors.New("no console output for this instance")
	}
	lines := strings.Split(strings.ReplaceAll(strings.TrimRight(string(b), "\n"), "\r", ""), "\n")
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	out := map[string]any{"status": status, "lines": lines}
	if why != "" {
		out["error"] = why
	}
	return out, nil
}

func tailParam(q string) int { n, _ := strconv.Atoi(q); return n }
