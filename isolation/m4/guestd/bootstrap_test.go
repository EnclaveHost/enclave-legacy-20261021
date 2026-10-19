package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/bootstrap"
)

func TestBootstrapCreateChoice(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"untrusted":"public"}`))
	for _, name := range []string{"direct", "disabled", "legacy-tree", "missing", "mixed-release", "mixed-ticket", "not-deployment", "oversized", "bad-base64"} {
		t.Run(name, func(t *testing.T) {
			s := &server{Release: true, DirectBootstrap: true}
			r := &Request{Bootstrap: encoded}
			hd := strings.Repeat("ab", 32)
			switch name {
			case "disabled":
				s.Release = false
			case "legacy-tree":
				s.DirectBootstrap = false
			case "missing":
				r.Bootstrap = ""
			case "mixed-release":
				r.Release = true
			case "mixed-ticket":
				r.Ticket = b64('x')
			case "not-deployment":
				hd = ""
			case "oversized":
				r.Bootstrap = strings.Repeat("a", 180000)
			case "bad-base64":
				r.Bootstrap = encoded + "\n"
			}
			ticket, legacy, err := s.releaseChoice(r, hd)
			if name == "direct" {
				if err != nil || ticket != nil || legacy {
					t.Fatalf("%v %v %v", ticket, legacy, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid mode")
			}
		})
	}
}

func TestBootstrapDeliveredOnlyToStartingInstance(t *testing.T) {
	r := newRig(t)
	r.s.Release, r.s.DirectBootstrap = true, true
	raw := []byte(`{"untrusted":"public"}`)
	var got []byte
	r.f.guest = func(ctx context.Context, cid uint32, hostData string) error {
		id, b, err := r.s.bootstrapForCID(cid)
		if err != nil {
			return err
		}
		if hex.EncodeToString(id[:]) != hostData {
			t.Error("wrong deployment")
		}
		got = b
		if !r.s.admitCID(cid) {
			t.Error("bootstrap RPC egress not admitted")
		}
		return nil
	}
	p, _ := r.bundle("A", contract.Policy{})
	code, v := r.do("POST", "/vms", map[string]any{"name": name(4), "image": "file://" + p, "bootstrap": base64.StdEncoding.EncodeToString(raw)})
	if code != 201 {
		t.Fatalf("%d %v", code, v)
	}
	r.s.launching.Wait()
	x := r.vm(v["id"].(string))
	if string(got) != string(raw) || x.Status != "running" || x.ticket != nil {
		t.Fatalf("%s %s", got, x.Status)
	}
	for _, cid := range []uint32{0, 4242, x.cid} {
		if _, _, err := r.s.bootstrapForCID(cid); err == nil {
			t.Fatal("served unrecognized or running guest")
		}
	}
	_, pub := r.do("GET", "/vms/"+x.ID, nil)
	if pub["directBootstrap"] != true || pub["release"] == true || pub["bootstrap"] != nil {
		t.Fatalf("wrong public mode: %v", pub)
	}
	s2, _, adopted, dropped := r.restart(t)
	if len(adopted) != 1 || len(dropped) != 0 {
		t.Fatalf("adopted %v dropped %v", adopted, dropped)
	}
	adoptedVM := s2.vms[x.ID]
	if !adoptedVM.directBootstrap || !s2.admitCID(adoptedVM.cid) || len(adoptedVM.bootstrap) != 0 || adoptedVM.ticket != nil {
		t.Fatal("restart lost mode or retained startup material")
	}
}

func TestBootstrapStoppedGuestGetsNothing(t *testing.T) {
	v := &vm{cid: 123, HostData: strings.Repeat("ab", 32), directBootstrap: true, bootstrap: []byte("untrusted"), Status: "starting", lc: contract.NewLifecycle(contract.Starting)}
	s := &server{vms: map[string]*vm{"a": v}}
	// The same lifecycle transition a delete during startup requests.
	v.lc.RequestEnd("test")
	if _, _, err := s.bootstrapForCID(123); err == nil {
		t.Fatal("ended guest received a package")
	}
}

func TestBootstrapWireService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := [32]byte{1}
	s := &server{vms: map[string]*vm{"a": {cid: 123, HostData: hex.EncodeToString(id[:]), directBootstrap: true, bootstrap: []byte("exact bytes"), Status: "starting", lc: contract.NewLifecycle(contract.Starting)}}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.serveBootstrap(ctx, l, func(net.Conn) uint32 { return 123 }) }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	b, err := bootstrap.ReadPackage(c, id)
	c.Close()
	if err != nil || string(b) != "exact bytes" {
		t.Fatalf("%s %v", b, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}
