# mainframe-nse

Nmap Scripting Engine (NSE) scripts for mainframe-adjacent protocols, starting
with TN3270E (the terminal protocol behind IBM z/OS, z/VM, CICS, and RACF/
ACF2/Top Secret logon screens).

## Why this exists

Nmap has no TN3270 or TN5250 protocol library. Unlike SMB, MS-SQL, or SSH,
there's nothing in stock Nmap that speaks the 3270 wire protocol at all —
which means a plain `nmap -sV` against port 23 or 992 on a mainframe just
reports an open port, nothing more.

This repo adds a purpose-built NSE script and supporting Lua library that
performs the actual TN3270E negotiation (device type, LU name, screen size)
and reads the first screen back, then classifies what's on the other end —
z/OS TSO, z/VM CMS, CICS, or which security manager (RACF, ACF2, Top Secret)
guards the logon.

## Relationship to WebTerm/3270

This is a sibling project to [`web3270`](../web3270), the WebTerm/3270
terminal emulator and security-testing bridge. That project already does
deep, stateful TN3270 work (RACF enumeration, dataset scanning, protocol
fuzzing, MITM, and more) but as an interactive terminal application, not a
network scanner. `mainframe-nse` deliberately does **not** try to port that
work into NSE — see `docs/FEASIBILITY.md` for why most of it doesn't fit
Nmap's single-host, one-shot scan model. What's here is the one slice that
does: passive protocol-level fingerprinting from a single connect, the same
shape as Nmap's own `-sV` version detection.

The banner/message-ID classification rules in `lib/tn3270.lua` are a
from-scratch Lua reimplementation, cross-checked against (not copied from)
`Bridge_server/public/js/rendering.js` (`_FP_RULES`) and
`Bridge_server/features/esm-fingerprint.js` (`RULES`) in the `web3270` repo.

## Scripts

- **`scripts/tn3270-info.nse`** — connects on 23 (plain) or 992 (TLS),
  performs TN3270E DEVICE-TYPE and FUNCTIONS sub-negotiation, reads the first
  inbound 3270 data record, and reports:
  - negotiated device type / model, LU name (requested vs. granted)
  - screen geometry
  - classified host type (TSO / z-VM / CICS / IMS / ISPF / SDSF / LOGON /
    unknown)
  - classified security manager, if a logon or error screen shows one
    (RACF / ACF2 / Top Secret / unknown)

  **Non-default port?** The script only fires on 23, 992, or a service Nmap
  already named `tn3270`/`tn3270s`. A mainframe on any other port usually gets
  labeled `unknown` or something unrelated, so the script is skipped silently.
  Tell it which ports to treat as TN3270E:

  ```bash
  nmap --script tn3270-info --script-args tn3270-info.ports=2023,4023 -p 2023,4023 <target>
  ```

  It does **not** report TLS cipher suite or certificate details on port 992
  — that's already covered by Nmap's own `ssl-cert` and `ssl-enum-ciphers`
  scripts. Run those alongside this one for the full picture.

## Status

Early / v1. See `docs/FEASIBILITY.md` for scope boundaries and
`docs/NEGOTIATION-NOTES.md` for the TN3270E sub-negotiation reference this
was built against. Public at https://github.com/wren-creator/mainframe-nse.

## Installing

Nmap finds `require`d libraries only in its own `nselib` directory, so copy
both files, and recopy `lib/tn3270.lua` after every pull (a stale copy is the
usual cause of odd errors):

```bash
sudo cp lib/tn3270.lua "$(nmap --datadir)/nselib/tn3270.lua"
sudo cp scripts/tn3270-info.nse "$(nmap --datadir)/scripts/tn3270-info.nse"
nmap --script tn3270-info -p23 <target>
```

## Testing

See `test/README.md` — run against the `web3270` project's mock LPAR
(`mock-lpar/mock-lpar.js` or `mock-zvm.js`) rather than a real host, since
there's no public TN3270E service safe to test against.

## License

GPLv3 — see `LICENSE`.
