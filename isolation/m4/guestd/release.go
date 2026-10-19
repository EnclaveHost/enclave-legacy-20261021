package main

// The attested release, host side (docs/security/attested-release.md; the guest side is isolation/m2/front/provision.go).
//
// A guest that serves a deployment gets its owner's config and secrets from the relay, sealed to a key only it holds,
// and nothing about them crosses this host. What this host does is carry two things it cannot misuse:
//
//   - the TICKET. The lease holder's supervisor gets it from the relay (it holds the operator key; this host does
//     not) and hands it to guestd; guestd hands it to the ONE guest it launched for that deployment, on vsock host
//     port release.TicketPort. A ticket is useless in any other guest (the relay binds it to a report that guest
//     cannot produce), but it is one-use, so a ticket routed to the wrong guest is BURNED: the service therefore
//     answers a guest only by the vsock CID guestd itself chose for it, and only with that guest's own deployment's
//     ticket. The guest's front refuses a ticket that does not name its HOST_DATA anyway.
//   - the guest's EGRESS, on vsock host port egressPort: TLS the guest runs end to end, to origins the guest's own
//     allowlist names (isolation/m2/egress). This host sees destinations, timing and volume, and records only the
//     guest's CID and an outcome code. It serves only CIDs of guests guestd launched (admitCID).
//
// The ticket arrives in one of two ways: in the create request, or later through POST /vms/<id>/ticket. The second is
// the one a supervisor should use: the guest dials the ticket service as it boots and guestd HOLDS that connection,
// reporting awaitingTicket, so the supervisor fetches the ticket (TTL 120 s at the relay) only once the guest is
// actually waiting, and no part of the TTL is spent building the image. A ticket that never arrives ends the guest:
// the hold times out, the connection closes, the front refuses to start the app, the guest powers off, and the
// launch fails through the lifecycle, returning the guest's reservation (pool.go).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"enclave.host/isolation/contract"
	"enclave.host/isolation/m2/release"
)

// egressPort is the host port of the egress server; it must equal the front's EgressPort (isolation/m2/front).
const egressPort = 9443

// The CIDs guestd gives its guests: a band of their OWN, above the 65536-131071 that m2/run-domain.sh draws from at
// random when a lab launch chooses one itself, so a lab VM can never take a CID guestd has promised (enclave-99).
const cidBase, cidSpan = 131072, 65536

// cidQuarantine: a freed CID is not handed out again for this long. reclaim does not wait on a unit's stop, so the old
// QEMU may still hold the CID for a moment after the instance is gone (enclave-99).
const cidQuarantine = 10 * time.Minute

// maxHeld bounds the ticket connections held at once across every guest (one per starting release guest is the norm).
const maxHeld = 64

// releaseLive: the instance may still be handed something NEW - a ticket, an egress connection. Starting or running,
// and no end requested: a DELETE during startup only RECORDS the end (startup still owns the guest and honours it on
// its way out), and until then nothing new may reach the guest (enclave-99's review of 21b41ff6).
func releaseLive(v *vm) bool {
	st := v.lc.State()
	return (st == contract.Starting || st == contract.Running) && !v.lc.EndRequested()
}

// pickCIDLocked chooses a vsock CID no guest this guestd holds uses - launched this run or ADOPTED from a previous
// one (their CIDs are restored with them, persist.go). Called with s.mu held.
func (s *server) pickCIDLocked() (uint32, error) {
	used := map[uint32]bool{}
	for _, v := range s.vms {
		if v.cid != 0 {
			used[v.cid] = true
		}
	}
	for c, freed := range s.freedCIDs {
		if s.Now().Sub(freed) < cidQuarantine {
			used[c] = true
		} else {
			delete(s.freedCIDs, c)
		}
	}
	draw := s.drawCID
	if draw == nil {
		draw = func() uint32 {
			var b [4]byte
			_, _ = rand.Read(b[:])
			return cidBase + binary.LittleEndian.Uint32(b[:])%cidSpan
		}
	}
	for i := 0; i < 64; i++ {
		if c := draw(); c >= cidBase && c < cidBase+cidSpan && !used[c] {
			return c, nil
		}
	}
	return 0, errors.New("no free vsock CID")
}

// parseTicket is a ticket as the relay issues it: base64 of 32 bytes.
func parseTicket(s string) ([32]byte, error) {
	var t [32]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return t, errors.New("a ticket is base64 of 32 bytes")
	}
	copy(t[:], raw)
	return t, nil
}

// offerTicket fills a starting guest's one ticket slot. A guest reads exactly one ticket, at boot, so a second offer
// is refused rather than queued.
func (s *server) offerTicket(v *vm, t [32]byte) error {
	s.mu.Lock()
	ok := v.ticket != nil && v.Status == "starting" && releaseLive(v)
	taken := v.ticketTaken
	s.mu.Unlock()
	if !ok {
		return errors.New("this instance is not a starting deployment guest that takes a ticket")
	}
	if taken {
		return errors.New("this instance's guest already took its ticket")
	}
	select {
	case v.ticket <- t:
		return nil
	default:
		return errors.New("a ticket is already pending for this instance")
	}
}

// takeTicket is what the ticket service does for the guest at CID cid: find the ONE instance guestd launched with
// that CID, wait (up to TicketHold) for its ticket, and return it bound to THAT instance's deployment. Another
// instance's ticket can never be returned: the slot read is the instance's own.
//
// gone closes when the guest's connection does: the hold then ends WITHOUT taking the ticket, which stays in the slot
// rather than being written to a dead socket (nil = no connection to watch, as in tests).
func (s *server) takeTicket(ctx context.Context, cid uint32, gone <-chan struct{}) (release.Ticket, *vm, error) {
	var out release.Ticket
	s.mu.Lock()
	var v *vm
	for _, o := range s.vms {
		if o.cid == cid && cid != 0 && o.ticket != nil && o.Status == "starting" && releaseLive(o) {
			v = o
			break
		}
	}
	switch {
	case v == nil:
		s.mu.Unlock()
		return out, nil, errors.New("no starting deployment guest has this CID")
	case v.ticketTaken:
		s.mu.Unlock()
		return out, v, errors.New("this guest already took its ticket")
	case v.awaitingTicket:
		s.mu.Unlock()
		return out, v, errors.New("this guest already holds a ticket connection")
	case s.held >= maxHeld:
		s.mu.Unlock()
		return out, v, errors.New("too many guests are waiting for tickets")
	}
	hd, err := hex.DecodeString(v.HostData)
	if err != nil || len(hd) != 32 {
		s.mu.Unlock()
		return out, v, errors.New("the instance has no deployment id")
	}
	copy(out.ID[:], hd)
	v.awaitingTicket = true
	s.held++
	s.mu.Unlock()
	defer s.set(v, func() { v.awaitingTicket = false; s.held-- })

	hold := s.TicketHold
	if hold <= 0 {
		hold = release.TicketHold // the front's wait (m2/front ticketWait) is derived from the same constant
	}
	timeout := time.NewTimer(hold)
	defer timeout.Stop()
	check := time.NewTicker(250 * time.Millisecond)
	defer check.Stop()
	for {
		// a guest that has left, or an instance whose end was asked for, takes nothing - checked before every wait, so a
		// ticket that arrives in the same instant is left in the slot rather than written to a dead socket
		select {
		case <-gone:
			return out, v, errors.New("the guest closed its ticket connection")
		default:
		}
		if !releaseLive(v) {
			return out, v, errors.New("the instance's end was asked for while its guest waited for a ticket")
		}
		select {
		case t := <-v.ticket:
			s.set(v, func() { v.ticketTaken = true })
			out.Ticket = t
			return out, v, nil
		case <-gone:
			return out, v, errors.New("the guest closed its ticket connection")
		case <-timeout.C:
			return out, v, errors.New("no ticket arrived for this guest")
		case <-ctx.Done():
			return out, v, ctx.Err()
		case <-check.C:
		}
	}
}

// serveTickets is the ticket service: one line per guest connection, then close. It logs the CID, the instance and
// the outcome, never a ticket.
func (s *server) serveTickets(ctx context.Context, l net.Listener, cidOf func(net.Conn) uint32, lg *log.Logger) error {
	if cidOf == nil {
		return errors.New("ticket service: cidOf is required (a ticket goes only to the guest guestd launched for it)")
	}
	go func() { <-ctx.Done(); l.Close() }()
	backoff := 5 * time.Millisecond
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return err
			}
			// EMFILE, ECONNABORTED, ...: transient. Ending here would restart guestd, whose boot sweep ends every
			// starting guest (enclave-99), so wait and accept again.
			lg.Printf("accept: %v (retrying in %s)", err, backoff)
			time.Sleep(backoff)
			if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			continue
		}
		backoff = 5 * time.Millisecond
		go func() {
			defer c.Close()
			cid := cidOf(c)
			// the guest sends nothing on this connection: a read that returns at all means it closed (or broke the
			// protocol), and then the hold ends without taking its ticket
			gone := make(chan struct{})
			go func() { var b [1]byte; _, _ = c.Read(b[:]); close(gone) }()
			t, v, err := s.takeTicket(ctx, cid, gone)
			id := "-"
			if v != nil {
				id = v.ID
			}
			if err != nil {
				lg.Printf("guest %d (instance %s): no ticket: %v", cid, id, err)
				return
			}
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := release.WriteTicket(c, t); err != nil {
				lg.Printf("guest %d (instance %s): the ticket was not delivered: %v", cid, id, err)
				return
			}
			lg.Printf("guest %d (instance %s): ticket delivered", cid, id)
		}()
	}
}

// admitCID is the egress server's Admit: only a guest this guestd launched for a deployment, while it lives.
func (s *server) admitCID(cid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.vms {
		// a RELEASE guest only (a legacy or lab guest has no allowlist of its own), and only while releaseLive: once its
		// end is requested - a DELETE during startup included - its guest gets no new connection
		if v.cid == cid && cid != 0 && v.release && v.HostData != "" && releaseLive(v) &&
			(v.Status == "starting" || v.Status == "running") {
			return true
		}
	}
	return false
}

// postTicket is POST /vms/<id>/ticket {ticket}: the supervisor's late ticket, once the instance reports awaitingTicket.
func (s *server) postTicket(w http.ResponseWriter, r *http.Request, id string) {
	if !s.Release {
		s.json(w, 422, map[string]any{"error": "this guestd does not deliver release tickets (-release is off)"})
		return
	}
	var b struct {
		Ticket string `json:"ticket"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		s.json(w, 400, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	t, err := parseTicket(b.Ticket)
	if err != nil {
		s.json(w, 422, map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	v := s.vms[id]
	s.mu.Unlock()
	if v == nil {
		s.json(w, 404, map[string]any{"error": "no such instance"})
		return
	}
	if err := s.offerTicket(v, t); err != nil {
		s.json(w, 409, map[string]any{"error": err.Error()})
		return
	}
	s.json(w, 202, map[string]any{"id": v.ID, "ticket": "pending"})
}

// releaseChoice decides, for one create, whether the guest is a RELEASE guest (this tree's image; a ticket slot) or a
// LEGACY one (the previous tree's image, on a -release guestd), and validates a create-time ticket.
//
// d1's rollout option (i): the relay's list is where an owner's decision lives, and the supervisor states it as
// `release`. On a -release guestd a deployment that is not a release guest is built from the legacy tree, so it runs
// exactly as before the release existed; with no legacy tree it is refused, because this tree's front will not start a
// deployment's app without a release. A lab guest (no deployment id) has no HOST_DATA and runs this tree's image with
// no release.
func (s *server) releaseChoice(req *Request, hostData string) (ticket *[32]byte, legacy bool, err error) {
	if req.Bootstrap != "" || s.DirectBootstrap && hostData != "" {
		if !s.Release || !s.DirectBootstrap || hostData == "" || req.Release || req.Ticket != "" {
			return nil, false, errors.New("direct bootstrap requires its dedicated tree and deployment, without relay release or ticket")
		}
		_, err := decodeBootstrap(req.Bootstrap)
		return nil, false, err
	}

	switch {
	case req.Release && !s.Release:
		return nil, false, errors.New("a release guest: this guestd does not deliver releases (-release is off)")
	case req.Release && hostData == "":
		return nil, false, fmt.Errorf("a release guest for %q, which is not a deployment id: the guest would have no HOST_DATA to bind", req.Name)
	case req.Ticket != "" && !req.Release:
		return nil, false, errors.New("a release ticket for a guest that is not a release guest (release is not set)")
	case s.Release && !req.Release && hostData != "":
		if s.Legacy == nil {
			return nil, false, errors.New("a deployment that is not a release guest: this -release guestd has no legacy image (-legacy-isolation), and its own front would not start the app without a release")
		}
		legacy = true
	}
	if req.Ticket != "" {
		t, err := parseTicket(req.Ticket)
		if err != nil {
			return nil, false, err
		}
		ticket = &t
	}
	return ticket, legacy, nil
}
