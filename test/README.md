# Testing tn3270-info.nse

There's no public TN3270E service safe to point a new script at, so this
gets tested against `web3270`'s mock LPAR servers instead. **Not yet run
end-to-end** — this documents how to do it, not a confirmed-passing result.

## 1. Install the library where Nmap can find it

`lib/tn3270.lua` isn't part of stock Nmap's `nselib`, so `require "tn3270"`
needs it placed somewhere Nmap's Lua search path covers. Simplest option,
copy it into your Nmap install's own library directory:

```bash
cp ~/git/mainframe-nse/lib/tn3270.lua "$(nmap --datadir)/nselib/tn3270.lua"
```

(`nmap --datadir` prints the directory, typically `/usr/local/share/nmap` or
`/opt/homebrew/share/nmap` on macOS Homebrew installs.) Re-run this after
any edit to `lib/tn3270.lua` — Nmap doesn't read it from this repo directly.

## 2. Start a mock target

From `web3270/Bridge_server`:

```bash
node mock-lpar/mock-lpar.js     # z/OS TSO/RACF mock, listens on tcp/3270
# or
node mock-lpar/mock-zvm.js      # z/VM mock, listens on tcp/3271
```

## 3. Run the script

```bash
nmap --script ~/git/mainframe-nse/scripts/tn3270-info.nse -p 3270 localhost
nmap --script ~/git/mainframe-nse/scripts/tn3270-info.nse -p 3271 localhost
```

(`--script <path>` works with an absolute/relative path directly, no need to
copy the `.nse` file into Nmap's own `scripts/` directory the way the
library has to be copied — only `require`d libraries need to be found via
Nmap's Lua path.)

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
`lib/tn3270.lua` isn't reading the first screen correctly — check
`result.log` (enable with `-d2` for `stdnse.debug2` output) to see the raw
negotiation trace before digging into the classification tables.

## Known gap

`mock-lpar.js`/`mock-zvm.js` don't serve TLS, so the port-992 TLS path in
`tn3270-info.nse` (`sock:connect(host, port, "ssl")`) is untested against
anything. If a TLS-front-ended mock gets added later, retest that path
specifically.
