# ibmi: TN5250 and IBM i (AS/400) recon scripts

NSE scripts for IBM i, the other half of the mainframe-adjacent world. The
parent repo covers z/OS over TN3270E. This subdirectory covers IBM i over
TN5250 and the IBM i host servers.

## Status

Four scripts, all run against a live IBM i 7.5 (PUB400) on 2026-10-18. Only one release and one customized sign-on screen have been seen so far, so expect surprises on other releases. See `ROADMAP.md` for the build order and
`docs/SCOPE.md` for what is in, what is out, and why.

## Why this exists

Nothing in stock Nmap speaks TN5250 or the IBM i host server protocols. A
plain `nmap -sV` against 23, 449 or 8476 on an IBM i reports an open port, or
a wrong service name (8470 to 8474 are labeled `cisco-avp`, `otv` and similar
in `nmap-services`). These scripts fix that, one connect at a time, with no
credentials.

## Rules of the road

- **No credentials, ever.** IBM i locks profiles (including `QSECOFR`) after
  `MAXSIGN` failed sign-ons. Nothing here sends a user ID or password, and
  there is no `brute` category script.
- **Single connect, read, report.** Same shape as `tn3270-info`.
- **Nothing that touches `as-rmtcmd` (8475)**, the remote command server.
- **Lean on stock Nmap for TLS.** Run `ssl-cert` and `ssl-enum-ciphers` on
  992 and 9470 to 9476 alongside these scripts.

## Layout

```
ibmi/
  README.md
  ROADMAP.md
  docs/      scope notes and wire-format notes
  test/      mock server for local runs
  lib/       Lua libraries (install into ~/.nmap/nselib/)
  scripts/   .nse scripts (install into ~/.nmap/scripts/)
```

Install the same way as the parent repo:

```bash
mkdir -p ~/.nmap/nselib ~/.nmap/scripts
cp lib/*.lua ~/.nmap/nselib/
cp scripts/*.nse ~/.nmap/scripts/
nmap --script tn5250-info -p 23,992 <target>
nmap --script ibmi-svrmap-info -p 449 <target>
nmap --script ibmi-signon-info -p 8476,9476 <target>
nmap -p 23,992,449,8470-8476,9470-9476 --script ibmi-hostservers <target>
```

Byte layouts, with what is confirmed and what is still a guess, are in
`docs/WIRE-NOTES.md`. Test steps and fixtures are in `test/README.md`.

Add `--script-args tn5250-info.dump=true` to get the screen text and raw
record bytes in the output, which is what to send along with a bug report.
 Library names get an `mf` prefix so they never
shadow anything Nmap ships.
