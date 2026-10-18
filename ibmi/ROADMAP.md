# Roadmap: IBM i / TN5250

Checkbox list. Entries stay short. Wire formats must be confirmed against a
real IBM i or a packet capture before a script is called done.

State as of 2026-10-18: all four scripts run against a live IBM i 7.5
(PUB400) and against web3270's mock AS/400. One release and one customized
sign-on screen is a thin base, so the next work is breadth and trust, not
more scripts.

## Next steps, in order

1. [ ] **Fixture regression script.** `test/run-fixtures.sh` replays every file in `test/fixtures/` through `tn5250-info` and checks the expected system, subsystem, device and label text. Today that check is by eye, and the two parser bugs so far both came from a parser edit that looked fine.
2. [ ] **Second release.** Run the four scripts on a release other than 7.5 (7.3 or 7.4 are the likely ones in the field). Needs a target and permission. Covers the password level table, the version encoding, and whether the CCSID field (0x1114) ever shows up.
3. [ ] **A real stock sign-on screen.** Everything so far is either PUB400's customized screen or a mock. A capture from an uncustomized system is the proof that the label parsing is not tuned to one site.
4. [ ] **Remediation notes per finding.** For each finding the scripts raise (plain telnet, plain-only host server, remote command server reachable, password level under 2), a short "what to change" in `docs/`, with the IBM command or system value named and a source. Findings without a fix attached are only half useful in a report.
5. [ ] **Engagement guide.** One page on using these under a ROE: the exact commands, what each one sends, `-oX` output into a findings table, and the lockout rule. The team will run these, so this is the doc they read first.
6. [ ] **Nmap service labels.** Let `ibmi-svrmap-info` tell Nmap what 8470 to 8476 really are (for example `nmap.set_port_version`), and write `-sV` probe lines, so a stock scan stops calling them `cisco-avp` and `otv`.
7. [ ] **Fold the EBCDIC tables together.** `lib/mf3270.lua` still has its own CP037 copy. Move it to `mfebcdic` once the ibmi work has settled.
8. [ ] **Decide about upstreaming.** Whether to offer the scripts to the Nmap project. Needs a licence decision (this repo is GPLv3, Nmap has its own) and the library names checked against Nmap's `nselib`.

## Groundwork

- [x] Test target: PUB400 (hosted IBM i 7.5) plus web3270's mock AS/400
- [x] Reference traffic captured for the TN5250 sign-on and the as-signon exchange; port 449 raw replies are in `docs/WIRE-NOTES.md`, not yet a fixture
- [x] `lib/mfebcdic.lua`: shared CP037 tables (the 3270 library still has its own copy, fold it in later)
- [x] `docs/WIRE-NOTES.md`: byte layouts, tagged confirmed, assumed or not seen

## Scripts

- [x] `lib/mf5250.lua` + `scripts/tn5250-info.nse` (ports 23, 992): checked against PUB400 (IBM i 7.5) on 23 and 992, 2026-10-18. Regression fixture in `test/fixtures/`. Sends no device name by default (a custom one can create a device description on the system), opt in with `tn5250-info.devname`
- [x] `scripts/ibmi-svrmap-info.nse` (449): checked against PUB400, 2026-10-18, all 14 lookups matched the documented ports. Uses `lib/mfibmi.lua`
- [x] `scripts/ibmi-signon-info.nse` (8476, 9476): checked against PUB400 on plain and TLS, 2026-10-18. Reports OS version, datastream level, password level and the server job name; never prints the server seed
- [x] `scripts/ibmi-hostservers.nse` (host rule): summarizes plain versus TLS port states for the host servers and telnet from Nmap's own scan results, makes no connections of its own. Checked against local listeners, no wire format involved

## Docs and tests

- [x] README install and usage lines for all four scripts
- [ ] A worked example of each script's output in the README (the `@output` blocks in the scripts are the source)
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

- [ ] Fold the TN5250 TLS sub-option report into `tn5250-info` rather than a separate script
- [ ] DRDA on 446: stock `drda-info` may already cover IBM i, check before building anything
- [ ] Other IBM i listeners that web3270's mock AS/400 models: HTTP admin (2001, 2010) and FTP (21, 990). Check what stock Nmap already reports for them and build only the gap
- [ ] Let `ibmi-svrmap-info` hand the ports it finds to the other scripts, so a non-default sign-on port is picked up without `--script-args ibmi-signon-info.ports=`
- [ ] Why plain 23 and TLS 992 land in different subsystems (QINTER and QINTER2 on PUB400), worth a note in the engagement guide if it holds elsewhere
- [ ] A credentialed, opt-in check, only if a ROE calls for it. It would be its own script, refuse to run without an explicit argument, and cap attempts well under `MAXSIGN`. No decision made, nothing built

## Ruled out

- Credential guessing of any kind (account lockout risk)
- Anything that talks to `as-rmtcmd` (8475)
- Multi-screen terminal navigation (see `../docs/FEASIBILITY.md`)
