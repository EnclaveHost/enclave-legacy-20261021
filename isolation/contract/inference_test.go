package contract

import "testing"

func TestInferenceModelReservation(t *testing.T) {
	for _, tc := range []struct {
		model      string
		min, floor int
	}{{ShieldModel, 65, 8192}, {Shield27BModel, 500, 73728}, {ShieldZImageModel, 100, 6144}} {
		for _, milli := range []int{0, tc.min - 1, tc.min, 1000, 1001} {
			i := &Inference{Model: tc.model, GPUMilli: milli}
			valid := milli >= tc.min && milli <= 1000
			if (i.Validate() == nil) != valid {
				t.Fatalf("%s/%d admission mismatch", tc.model, milli)
			}
			if i.GuestFloorMiB() != tc.floor {
				t.Fatal("wrong model RAM floor")
			}
			if valid && i.CardBytes() != ShieldCardBytes*int64(milli)/1000 {
				t.Fatal("wrong per-card reservation")
			}
		}
	}
	if (&Inference{Model: "host-selected-model", GPUMilli: 1000}).Validate() == nil {
		t.Fatal("unmeasured model admitted")
	}
}
