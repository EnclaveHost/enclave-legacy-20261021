package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The Z-Image Shield model on NucBox: its three files live on a read-only disk the host attaches to the partition (a
// fixed VHD whose data is the dm-verity volume metal/volumes.mjs builds: ext4, then its hash tree). This measured image
// pins the volume's root hash in <plat>/rt-shield-sd/shield-volume; the monitor opens the disk through dm-verity
// against that root (/mverity, raw device-mapper ioctls) and mounts the ext4 read-only under <plat>/models/<model>,
// which every domain's read-only bind of <plat> then carries. A block that does not hash to the pinned tree fails its
// read (EIO): the host can withhold the model or attach the wrong disk, never change a byte of it. Nothing about the
// disk comes from the host's request: which disk is found by trying each attached SCSI disk large enough to hold the
// pinned layout, and only the pinned root can open one.

const shieldVolumeTool = "/mverity"

// shieldVolume is one line of <plat>/rt-shield-sd/shield-volume: model alg root salt dataBlockSize hashBlockSize
// dataBlocks hashStartBlock (the build script writes it from volumes.mjs's volume.json).
type shieldVolume struct {
	model, alg, root, salt    string
	dbs, hbs, dblocks, hstart uint64
}

func parseShieldVolume(b []byte) (shieldVolume, error) {
	f := strings.Fields(string(b))
	var v shieldVolume
	if len(f) != 8 {
		return v, errors.New("the measured volume descriptor needs 8 fields")
	}
	v.model, v.alg, v.root, v.salt = f[0], f[1], f[2], f[3]
	nums := []*uint64{&v.dbs, &v.hbs, &v.dblocks, &v.hstart}
	for i, p := range nums {
		n, err := strconv.ParseUint(f[4+i], 10, 64)
		if err != nil || n == 0 {
			return v, fmt.Errorf("volume descriptor field %d is not a positive number", 5+i)
		}
		*p = n
	}
	if v.alg != "sha256" || !isHexLen(v.root, 64) || !isHexLen(v.salt, 64) || v.dbs != 4096 || v.hbs != 4096 || v.hstart <= v.dblocks {
		return v, errors.New("the measured volume descriptor is not a sha256 4 KiB verity layout")
	}
	return v, nil
}

func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// minBytes is the smallest disk that can hold the data and the hash tree's first block.
func (v shieldVolume) minBytes() uint64 { return (v.hstart + 1) * v.hbs }

// shieldModelDir is where the model's files appear for every domain (the sd graph's directory).
func (m *monitor) shieldModelDir(model string) string { return filepath.Join(m.plat, "models", model) }

// mountShieldVolume opens and mounts a model's verity volume once per boot. Domains created before a failure see none.
func (m *monitor) mountShieldVolume(model string) error {
	m.volMu.Lock()
	defer m.volMu.Unlock()
	if m.volMounted[model] {
		return nil
	}
	desc, err := os.ReadFile(filepath.Join(m.plat, "rt-shield-sd", "shield-volume"))
	if err != nil {
		return fmt.Errorf("this measured image pins no model volume: %w", err)
	}
	v, err := parseShieldVolume(desc)
	if err != nil {
		return err
	}
	if v.model != model {
		return fmt.Errorf("this measured image pins the volume of %s, not %s", v.model, model)
	}
	disks, _ := filepath.Glob("/sys/block/sd*")
	var tried []string
	for i, sys := range disks {
		b, err := os.ReadFile(filepath.Join(sys, "size"))
		if err != nil {
			continue
		}
		sectors, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil || sectors*512 < v.minBytes() {
			continue
		}
		dev := "/dev/" + filepath.Base(sys)
		name := fmt.Sprintf("shield%d", i)
		out, err := exec.Command(shieldVolumeTool, name, dev, strconv.FormatUint(v.dbs, 10), strconv.FormatUint(v.hbs, 10),
			strconv.FormatUint(v.dblocks, 10), strconv.FormatUint(v.hstart, 10), v.alg, v.root, v.salt).CombinedOutput()
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s: %v %s", dev, err, strings.TrimSpace(string(out))))
			continue
		}
		dir := m.shieldModelDir(model)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		// noload: no journal replay (the volume is read-only and the host must not be able to make us write)
		if err := syscall.Mount("/dev/mapper/"+name, dir, "ext4", syscall.MS_RDONLY|syscall.MS_NODEV|syscall.MS_NOSUID|syscall.MS_NOEXEC, "noload"); err != nil {
			tried = append(tried, fmt.Sprintf("%s: verity opened but the filesystem did not mount (wrong disk or bytes): %v", dev, err))
			continue
		}
		if m.volMounted == nil {
			m.volMounted = map[string]bool{}
		}
		m.volMounted[model] = true
		fmt.Printf("MON Shield model volume %s: dm-verity root %s on %s, mounted read-only\n", model, v.root, dev)
		return nil
	}
	if len(tried) == 0 {
		return fmt.Errorf("no attached disk is large enough for the %s volume (%d bytes)", model, v.minBytes())
	}
	return fmt.Errorf("no attached disk opened as the pinned %s volume: %s", model, strings.Join(tried, "; "))
}
