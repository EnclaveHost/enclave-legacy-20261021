# Direct bootstrap hardware transport

This lab runs alongside production guestd without reusing its vsock ports or
guest prefix. It retains real measured Base RPCs and certificate roots. It
does not fabricate chain state, attestation, leases or owner commitments.

Build a separate release with:

```sh
ISOLATION_DIRECT_BOOTSTRAP=1 ISOLATION_BOOTSTRAP_PORT_LAB=1 \
  sh isolation/m4/domain-release.sh /absolute/path/to/new-release
```

The guest's measured ports are egress 19443, custody authorization 19445 and
package transport 19446. The `rt/bootstrap-lab-ports` marker is included in
the measured release. Use a separate guestd root, pair key, instance prefix,
control listener and explicit resource budget. Never reuse production guest
IDs or lower the production host-memory floor for this test.

For the denial phase, run the lab guestd's egress listener on 19447 and run
this broker on 19443:

```sh
cd isolation/m2
go build -o /absolute/path/to/lab-egress ./lab-bootstrap/egress
/absolute/path/to/lab-egress --cid-file /absolute/path/to/admitted-cid
```

The CID file must contain only the assigned lab guest's CID, in the guestd
range 131072–196607. Start with no file, then write it when the launcher emits
the CID. A missing or invalid file refuses all guests. The broker exercises
the actual outbound dial path against four Enclave control names at startup
and exits if any succeeds. It permits only measured chain peer hostnames;
the standard egress dialer continues to enforce public-address and port rules.

Destroy the baseline guest before launching the denial-phase guest. Check
fresh hardware attestation, then match the peer's SPKI to the verified
transport binding before sending the application request. Save the serial
log, judge result, broker log and transaction receipts. Stop the lab guest,
both lab services and the paid test lease; refund any unused credit.

This test only denies the guest's control egress. A warm host artifact cache
or a local package broker is not independent storage evidence. A public
startup package does not exercise custody. Record these limits alongside
the result rather than presenting this as complete decentralization.
