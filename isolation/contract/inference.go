package contract

import (
	"fmt"
	"sort"
)

// Inference is measured with the app. No worker address or host environment is
// accepted here: the release fixes the private broker routes and public model.
type Inference struct {
	Model    string `json:"model"`
	GPUMilli int    `json:"gpuMilli"`
}

const ShieldModel = "qwen2.5-0.5b-q8-gguf"
const Shield27BModel = "qwen3.8-27b-mtp-q4-vl-gguf"

// Z-Image-Turbo (stable-diffusion.cpp): DiT + Qwen3-4B text encoder + VAE, three
// files, both GGUFs Q4_K_M (EnclaveHost/z-image-turbo-q4km-sd). Its offloaded
// DiT weights are 4.85 GiB of int8 rows plus 0.41 GiB of scratch, split over
// both cards: 2.77 GiB per card at the 0.95 budget fraction = 89 milli; 100
// leaves headroom for the worker's own overhead.
const ShieldZImageModel = "z-image-turbo-q4km-sd"

// The measured Shield models and their admission constants. A model is not
// admitted because a host names it; it is admitted because it is in this table
// AND a verified release packages it (the guest manager's rt/shield-model).
type shieldProfile struct {
	minMilli int // smallest per-card share its weights and scratch fit in
	floorMiB int // guest RAM the measured runtime needs before any app memory
}

var shieldProfiles = map[string]shieldProfile{
	ShieldModel: {65, 8192},
	// Includes 128-pad pools and both ordinary/MTP contexts, each with
	// eight active, six conversation and eight shared-prefix state slots.
	Shield27BModel: {500, 73728},
	// The private RAM copy of all three files (7.3 GiB), the int8 encoded
	// weights the backend keeps for its local fallback, pad pools for 64-row
	// chunks and 1024px activations.
	ShieldZImageModel: {100, 6144},
}

// IsShieldModel reports whether a model is in the measured Shield table.
func IsShieldModel(model string) bool {
	_, ok := shieldProfiles[model]
	return ok
}

// ShieldModels lists the table, sorted, for health and allowlists.
func ShieldModels() []string {
	out := make([]string, 0, len(shieldProfiles))
	for m := range shieldProfiles {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func (i *Inference) GuestFloorMiB() int {
	if i != nil {
		if p, ok := shieldProfiles[i.Model]; ok {
			return p.floorMiB
		}
	}
	return 8192
}

const ShieldCardBytes int64 = 31 << 30
const ShieldMinBytes int64 = 2 << 30

func (i *Inference) Validate() error {
	if i == nil {
		return nil
	}
	p, ok := shieldProfiles[i.Model]
	if !ok {
		return fmt.Errorf("unsupported isolated inference model %q", i.Model)
	}
	minimum := p.minMilli
	if i.GPUMilli < minimum || i.GPUMilli > 1000 {
		return fmt.Errorf("isolated inference requires gpuMilli in %d..1000", minimum)
	}
	return nil
}

// Each physical worker reserves the same share. Round down bytes, consistently
// with the worker protocol; admission accounts for both cards separately.
func (i *Inference) CardBytes() int64 {
	if i == nil {
		return 0
	}
	return ShieldCardBytes * int64(i.GPUMilli) / 1000
}
