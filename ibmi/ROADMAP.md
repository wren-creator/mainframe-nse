# Roadmap: IBM i / TN5250

Checkbox list, in build order. Entries stay short. Wire formats must be
confirmed against a real IBM i or a packet capture before a script is called
done. Nothing below has been verified yet.

## Groundwork

- [ ] Pick the test target: real IBM i, hosted IBM i, or captures only
- [ ] Capture reference traffic for TN5250 sign-on, port 449 lookups, and the as-signon exchange
- [x] `lib/mfebcdic.lua`: shared CP037 tables (the 3270 library still has its own copy, fold it in later)
- [ ] `docs/WIRE-NOTES.md`: confirmed byte layouts, with the source for each

## Scripts

- [~] `lib/mf5250.lua` + `scripts/tn5250-info.nse` (ports 23, 992): written and passing against `test/mock-tn5250.py`, NOT yet checked against a real IBM i. Sends no device name by default (a custom one can create a device description on the system), opt in with `tn5250-info.devname`
- [ ] `scripts/ibmi-svrmap-info.nse` (449): ask the server mapper for each host server by name, report the ports
- [ ] `lib/mfibmi.lua` + `scripts/ibmi-signon-info.nse` (8476, 9476): exchange attributes request, report server version, password level, whether it answers without auth
- [ ] `scripts/ibmi-hostservers.nse` (8470 to 8476, 9470 to 9476): which servers answer plain versus TLS, flag any plain-text exposure

## Docs and tests

- [ ] README install and usage section per script, once each exists
- [ ] Test notes: how each script was checked, against what
- [ ] Handle non-US EBCDIC code pages on the sign-on screen (CP273, CP500 and friends)

## Verify against a real system (PUB400 or a capture)

- [ ] SOH length byte: does it count itself? (`parse_orders`, marked UNVERIFIED)
- [ ] RA fill: inclusive or exclusive of the target address
- [ ] EA, TD and WDSF length conventions
- [ ] Does the server send a 5250 Query (WSF) that has to be answered before the sign-on screen appears?
- [ ] Does it need a proactive WILL from us, or is respond-only enough?
- [ ] Sign-on label parsing on other releases and customized sign-on screens
- [ ] Run once with `tn5250-info.dump=true` and keep the raw record as a test fixture

## Ideas, not committed

- [ ] A `-sV` service-probe contribution so Nmap labels 8470 to 8476 correctly
- [ ] Fold the TN5250 TLS sub-option report into `tn5250-info` rather than a separate script
- [ ] DRDA on 446: stock `drda-info` may already cover IBM i, check before building anything

## Ruled out

- Credential guessing of any kind (account lockout risk)
- Anything that talks to `as-rmtcmd` (8475)
- Multi-screen terminal navigation (see `../docs/FEASIBILITY.md`)
