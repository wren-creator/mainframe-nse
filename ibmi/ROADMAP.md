# Roadmap: IBM i / TN5250

Checkbox list, in build order. Entries stay short. Wire formats must be
confirmed against a real IBM i or a packet capture before a script is called
done. Nothing below has been verified yet.

## Groundwork

- [ ] Pick the test target: real IBM i, hosted IBM i, or captures only
- [ ] Capture reference traffic for TN5250 sign-on, port 449 lookups, and the as-signon exchange
- [x] `lib/mfebcdic.lua`: shared CP037 tables (the 3270 library still has its own copy, fold it in later)
- [x] `docs/WIRE-NOTES.md`: byte layouts, tagged confirmed, assumed or not seen

## Scripts

- [x] `lib/mf5250.lua` + `scripts/tn5250-info.nse` (ports 23, 992): checked against PUB400 (IBM i 7.5) on 23 and 992, 2026-10-18. Regression fixture in `test/fixtures/`. Sends no device name by default (a custom one can create a device description on the system), opt in with `tn5250-info.devname`
- [x] `scripts/ibmi-svrmap-info.nse` (449): checked against PUB400, 2026-10-18, all 14 lookups matched the documented ports. Uses `lib/mfibmi.lua`
- [x] `scripts/ibmi-signon-info.nse` (8476, 9476): checked against PUB400 on plain and TLS, 2026-10-18. Reports OS version, datastream level, password level and the server job name; never prints the server seed
- [x] `scripts/ibmi-hostservers.nse` (host rule): summarizes plain versus TLS port states for the host servers and telnet from Nmap's own scan results, makes no connections of its own. Checked against local listeners, no wire format involved

## Docs and tests

- [ ] README install and usage section per script, once each exists
- [x] Test notes: `test/README.md`
- [ ] Handle non-US EBCDIC code pages on the sign-on screen (CP273, CP500 and friends)

## Verify against a real system (PUB400 or a capture)

- [x] SOH length byte does not count itself (PUB400 capture)
- [x] Read MDT Fields (04 52, two control bytes) ends the sign-on record; no 5250 Query seen, respond-only negotiation was enough (PUB400)
- [x] Screen grid must match the terminal size, 24x80 for IBM-3179-2
- [ ] RA fill: inclusive or exclusive of the target address
- [x] Start field: length only follows an FFW (input fields), output-only fields have none
- [ ] EA, TD and WDSF length conventions
- [x] Port mapper: bare ASCII name in, 0x2B plus 4-byte big-endian port out, `-s` secure names (PUB400)
- [ ] What the port mapper sends back for an unknown name
- [ ] Does the mapper allow several lookups on one connection, or one per connection?
- [x] Sign-on server request and reply layouts (PUB400): reply id is F003, 1114 is not sent, 111F is the server job name, version encoding holds, random seed accepted
- [ ] CCSID (0x1114): which releases send it, if any
- [ ] Password level 4 and any newer levels: meaning, so the text table is complete
- [x] Sites rename sign-on labels (PUB400: "Server name", "Display name", "Your user name:"), parser now allows that
- [ ] Sign-on label parsing on more releases and other customized screens
- [x] Raw record kept as a test fixture
- [x] Second fixture, stock-style layout, from web3270's mock AS/400 (a mock, not a real system)
- [ ] A fixture from a real stock (uncustomized) sign-on screen
- [ ] A fixture for the port mapper replies (raw hex is in `docs/WIRE-NOTES.md` for now)
- [ ] Look into why plain 23 and TLS 992 land in different subsystems (QINTER vs QINTER2 on PUB400)
- [x] `ibmi-signon-info` run on 8476 and 9476
- [ ] Try the sign-on and port mapper scripts on a release other than 7.5

## Ideas, not committed

- [ ] A `-sV` service-probe contribution so Nmap labels 8470 to 8476 correctly
- [ ] Fold the TN5250 TLS sub-option report into `tn5250-info` rather than a separate script
- [ ] DRDA on 446: stock `drda-info` may already cover IBM i, check before building anything

## Ruled out

- Credential guessing of any kind (account lockout risk)
- Anything that talks to `as-rmtcmd` (8475)
- Multi-screen terminal navigation (see `../docs/FEASIBILITY.md`)
