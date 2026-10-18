# Feasibility map: WebTerm/3270 security tools → Nmap NSE scripts

This is the analysis that led to this repo existing at all. It sorts the
`web3270` project's full security-tools backlog (15 waves, ~30 tools) against
what actually fits Nmap's execution model, so nothing gets rebuilt that Nmap
already does, and nothing gets attempted that Nmap's architecture can't
support.

Two facts drive the whole analysis:

1. **Nmap has no TN3270 or TN5250 protocol library.** Unlike SMB, MS-SQL, or
   SSH, there is no `tn3270.lua`/`stdnse` module to build on. Any NSE script
   that needs to speak the actual 3270/5250 datastream (BIND-image, field
   attributes, orders, EBCDIC translation) means writing that protocol
   library from scratch in Lua — this repo's `lib/mf3270.lua` is that
   from-scratch work, not a port of anything.
2. **NSE scripts are single-host, short-timeout, and stateless-by-design.**
   They're built for one connect → probe → classify → done, not for driving
   a multi-screen, authenticated terminal session (TSO logon → ISPF → SDSF
   navigation, paging through `MORE`, drill-down detail screens).

## Category A — Good NSE fit (protocol-level, single connect, no auth)

These are the only backlog items that match NSE's actual shape: connect, do
one negotiation/read, pattern-match, report. **This is what `mainframe-nse`
v1 builds.**

- **TN3270E Negotiation Analyzer + host/security-manager fingerprinting** —
  connect, negotiate device type/LU-name/screen-size, read the first screen,
  classify TSO/z-VM/CICS/RACF/ACF2/TopSecret from banner text. Nothing in
  stock Nmap does TN3270E negotiation today — this is the one genuinely
  non-duplicate opportunity.

## Category B — Only partially new (Nmap already covers most of it)

- **Port 992 TLS/cert inspection.** Cipher suite negotiation and full cert
  chain are already fully covered by Nmap's built-in `ssl-cert` and
  `ssl-enum-ciphers` scripts. Rebuilding that would be pure duplication. The
  only non-duplicate slice — which TN3270E sub-options rode inside the TLS
  session — folds into `tn3270-info.nse` as an extra field rather than
  becoming its own script.
- **SSH no-credential access checking** (was backlog item #24, never built).
  Nmap's `ssh-auth-methods` and `ssh2-enum-algos` already enumerate offered
  auth methods and cover nearly all of what this item was after. **Dropped
  from consideration entirely** — not part of this repo.

## Category C — Poor NSE fit (stateful, authenticated, multi-screen)

Everything requiring a logged-in, multi-panel TSO/ISPF/SDSF/CICS/z-VM session
doesn't fit NSE's one-shot model, and would need the full 3270 datastream
decoder (not just the negotiation layer) this repo's v1 deliberately skips.
These stay in `web3270`/`Bridge_server` as bridge features, not NSE script
candidates:

RACF User/Group Enumerator, Dataset Recon Scanner, APF Library/PARMLIB
checks, CICS Transaction Scanner, SDSF Job Output Harvester, Started Task
Profile Scanner, VTAM Applid Enumerator, RACF-DB2/Connection Permission
probes, Buffer Bleed / Field Disclosure / VM Minidisk detectors, GDDM
detector+renderer, Wire Inspector correlator, MITM live traffic
modification, Pool/Exhaustion dashboard, and the full IBM i (AS/400)
security suite.

The unauthenticated slice of IBM i does fit NSE, and lives in `ibmi/`: the
sign-on screen over TN5250, the server mapper, the sign-on server, and the
host server port exposure. The authenticated IBM i work stays out.

The RACF credential probe and RACF timing attack sit at the edge — Nmap does
have precedent for wordlist-style `brute` category scripts (`ssh-brute`,
`ftp-brute`), but there's still no 3270 auth-handshake library to hang that
on. Revisit only after `lib/mf3270.lua` grows a full field/AID-send layer,
which is out of scope for v1.

## Recommendation

Build `scripts/tn3270-info.nse` + `lib/mf3270.lua` (Category A). Treat the
Category B TLS overlap as a documentation note, not a script. Leave Category
C alone indefinitely — it belongs to `web3270`, not this repo.
