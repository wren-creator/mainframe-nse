# Testing tn3270-info.nse

There's no public TN3270E service safe to point this at, so it's tested
against `web3270`'s mock LPAR servers instead. **This has been run
end-to-end** against both mocks (see "Verified results" below) — this isn't
just a plan, it's also the record of what that testing found and fixed.

## 1. Install the library where Nmap can find it

`lib/mf3270.lua` isn't part of stock Nmap's `nselib`, so `require "mf3270"`
needs it placed somewhere Nmap's Lua search path covers. Copy it into
your user Nmap directory:

```bash
mkdir -p ~/.nmap/nselib ~/.nmap/scripts
cp ~/git/mainframe-nse/lib/mf3270.lua ~/.nmap/nselib/
```

(`~/.nmap` is one of the places Nmap looks automatically, so no `sudo` and no
hunting for the Homebrew Cellar path.) Re-run this cp after any edit to `lib/mf3270.lua` — Nmap doesn't read it from
this repo directly, only from wherever this copy lands.

## 2. Start a mock target

From `web3270/Bridge_server`:

```bash
node mock-lpar/mock-lpar.js     # z/OS TSO/RACF mock, listens on tcp/3270
# or
node mock-lpar/mock-zvm.js      # z/VM mock, listens on tcp/3271
```

## 3. Run the script

**The real script's portrule only matches port 23, port 992, or a service
literally named `tn3270`/`tn3270s`** — the mocks' default ports (3270/3271)
match neither, and both real TN3270E ports are privileged (need root to
bind). Two ways to actually run it locally:

**A — real port, real script, needs sudo both sides:**

```bash
sudo MOCK_PORT=23 node mock-lpar/mock-lpar.js
sudo nmap --script ~/git/mainframe-nse/scripts/tn3270-info.nse -p23 localhost
```

**B — mock's default port, no sudo, using the local-test variant:**

```bash
nmap --script ~/git/mainframe-nse/test/tn3270-info-local.nse -p 3270 localhost
nmap --script ~/git/mainframe-nse/test/tn3270-info-local.nse -p 3271 localhost
```

`test/tn3270-info-local.nse` is committed in this repo specifically so this
doesn't need regenerating by hand each time — it's the same script, sharing
all its logic with the real one via `tn3270.scan()` in `lib/mf3270.lua`, just
with `3270`/`3271` added to its portrule. Never point it at anything but a
local mock.

(`--script <path>` works with an absolute/relative path directly for the
`.nse` file itself, no need to copy it into Nmap's own `scripts/` directory —
only `require`d libraries need to be found via Nmap's Lua path.)

## 4. Cross-check the verdict

Compare `hostType`/`securityManager` in the script's output against what
`web3270`'s own WebTerm UI reports for the same mock:

- Connect the WebTerm client to the same mock LPAR.
- The OIA bar's APP field (driven by `public/js/rendering.js`
  `_fingerprintScreen`) should show the same host-type classification
  (TSO/RACF/etc.) for the initial screen.
- The Security panel's ESM Fingerprint section (`esm-fingerprint.js`) should
  agree on which security manager, if any, the mock is presenting.

A mismatch means either a Lua pattern was translated wrong from the
JS `_FP_RULES`/`RULES` tables, or the negotiation/EBCDIC-extraction layer in
`lib/mf3270.lua` isn't reading the first screen correctly — check
`result.log` (enable with `-d2` for `stdnse.debug2` output) to see the raw
negotiation trace before digging into the classification tables.

## Verified results (2026-09-26)

Both mocks tested via option B above. Three real bugs turned up and got
fixed before anything was committed:

1. **Mutual re-ack infinite loop against the z/OS mock.** It has no
   negotiation-state tracking on its side — when the client's `WILL BINARY`/
   `WILL EOR` acks came back in, its `handleTelnetCmd` treated them as fresh
   offers and replied with another `DO BINARY`/`DO EOR`, which the client
   then re-acked, forever, at 100% CPU. Fixed with idempotency guards in
   `tn3270.negotiate()` (a `sent` table — same shape as `session.js`'s own
   `_willSend`/`_doSent` flags) so every option is only ever acked once.
2. **False ACF2 classification on a real RACF screen.** The JS original's
   ACF2 "ACF LOGON" rule uses `\bACF\s+LOGON\b` (word-bounded, so it can't
   match inside "**R**ACF LOGON"); the Lua translation dropped the boundary
   (Lua patterns have no `\b`), so it substring-matched inside the mock's
   real "RACF LOGON parameters:" banner. Fixed with `%f[%a]`/`%f[%A]`
   frontier patterns (Lua's equivalent) on every ACF2 rule that could
   collide with "RACF": `acf2-word`, `acf2-msgid`, `acf2-logon-hdr` in both
   `ESM_RULES` and `HOST_RULES`.
3. **z/VM mock never sends a `SEND DEVICE-TYPE` prompt.** It only implements
   the client-initiates style (`subCmd === TN3E_DEVICE_TYPE && payload[2]
   === TN3E_REQUEST`, unprompted) — matching what `session.js`'s own client
   does (`_sendTn3270eDeviceType()`, called unconditionally, never waiting to
   be asked). `tn3270.negotiate()` originally only reacted to a `SEND`
   prompt. Fixed by extracting `send_device_type_request_once()` and calling
   it proactively right after `WILL TN3270E`, guarded so it's a no-op if a
   `SEND` prompt shows up anyway (covers hosts that do it the mock-lpar.js
   way).

After those three fixes, both mocks come back clean:

- **z/OS mock (port 3270):** `tn3270e: true`, `deviceType: IBM-3278-2`,
  `hostType: RACF`, `securityManager: RACF (71% confidence)`, evidence
  `RACF LOGON PARAMETERS`. The 71% is an exact match against
  `esm-fingerprint.js`'s own math on its `RACF_LOGON` test fixture:
  score 10 (weight 6 `racf-logon-hdr` + weight 4 `racf-word`) against
  `10/(10+0+4) = 0.714`.
- **z/VM mock (port 3271):** `tn3270e: true`, `deviceType: IBM-3278-2`,
  `luGranted: ZVMLU01`, `hostType: z/VM`.

## Classic TN3270 / TERMINAL-TYPE hosts (2026-10-17)

A class host (c3270 connected fine, the script timed out with "no data
received during TN3270E negotiation") turned out to be a classic-style host:
`DO TERMINAL-TYPE`, then `SB TERMINAL-TYPE SEND`, then silence until the
client answers with `SB TERMINAL-TYPE IS <name>`. `handle_subneg()` dropped
every non-TN3270E subnegotiation, so that reply was never sent. Fixed: it now
answers `IBM-<model>` (up to 3 times, in case a host cycles its type list).

The web3270 mocks only exercise the TN3270E path, so this was reproduced with
a throwaway fake host (not committed): it sends `DO TTYPE` + `SB TTYPE SEND`,
refuses to send a screen until it sees `SB TTYPE IS`, then sends `DO/WILL
EOR`/`BINARY` and an EBCDIC "RACF LOGON PARAMETERS" screen ending in
`IAC EOR`. Before the fix: host times out, script prints nothing. After: the
script reports `tn3270e: false`, `deviceType: (classic TN3270, no
TN3270E)`, `securityManager: RACF`. Both web3270 mocks re-checked, results
unchanged. Remember to recopy `lib/mf3270.lua` into `nselib` after pulling
this.

## FUNCTIONS counter-proposal (2026-10-17)

First run against the real class host (nmap -sV: "IBM Telnet TN3270
(TN3270E)") timed out. The failure trace showed the DEVICE-TYPE handshake
finishing (LU `TCP00021` assigned) and then the host answering our
`FUNCTIONS REQUEST [DATA-STREAM-CTL]` with its own, empty `FUNCTIONS
REQUEST`. RFC 2355 makes the client accept a counter-proposal with
`FUNCTIONS IS <same list>`; we never did, so z/OS never sent the screen.
`handle_subneg()` now answers (capped at 3). Reproduced with a throwaway fake
host replaying that exact byte sequence (not committed): before the fix it
saw no `FUNCTIONS IS`, after, it sent the screen and the script classified
RACF. Classic-host fake and both web3270 mocks re-checked, unchanged.

## VTAM logon menu (2026-10-17)

With negotiation working, the class host (an IBM ADCD z/OS V2R5 lab
emulator, not a production system) came back `hostType: unknown`. Its first
screen is a VTAM application-selection menu ("VTAM Terminal = TCP00011",
"Enter L followed by the APPLID", example APPLIDs like `L TSO`/`L CICSTS56`),
which none of the rules covered. Added a `VTAM` rule at the top of
`HOST_RULES` (it has to outrank CICS/TSO, since the menu's own examples
would otherwise match those) and an `osVersion` field parsed from a
`z/OS VnRn` banner. That menu names no security manager, so no
`securityManager` line is correct. Checked with the fake host replaying that
screen text; mocks and the classic fake host unchanged.

## Known gap

`mock-lpar.js`/`mock-zvm.js` don't serve TLS, so the port-992 TLS path in
`tn3270.scan()` (`sock:connect(host, port, "ssl")`) is still untested against
anything. If a TLS-front-ended mock gets added later, retest that path
specifically.
