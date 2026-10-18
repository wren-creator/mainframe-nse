# Testing the ibmi scripts

Two kinds of evidence, and they are not the same weight:

1. **Live captures** (`fixtures/`): bytes from a real IBM i. These are the
   truth.
2. **Mock servers** (`mock-*.py`): written from my reading of the protocol.
   They prove a script and its mock agree with each other, nothing more.

Install first (from the `ibmi/` folder):

```bash
mkdir -p ~/.nmap/nselib ~/.nmap/scripts
cp lib/*.lua ~/.nmap/nselib/ && cp scripts/*.nse ~/.nmap/scripts/
```

Re-run that after every edit. Nmap reads the copies in `~/.nmap`, not the repo.

## Replay a real capture

```bash
python3 test/mock-tn5250.py 2323 test/fixtures/pub400-23-signon-record.hex &
nmap -Pn -p 2323 --script tn5250-info \
  --script-args tn5250-info.ports=2323,tn5250-info.dump=true 127.0.0.1
pkill -f mock-tn5250
```

Expected: `systemName: PUB400`, `subsystem: QINTER`, `displayDevice: QPADEV0067`,
`releaseHintFromBanner: 7.5`, `gridSize: 24x80`, commands
`clear-unit,write-to-display,read-mdt-fields`. If any of that changes, a parser
edit broke something that used to work on a real system.

Without the hex argument, the mock sends a small synthetic sign-on screen.

## Other mocks

```bash
python3 test/mock-svrmap.py 2449 &     # port mapper, a few servers with no TLS twin
nmap -Pn -p 2449 --script ibmi-svrmap-info --script-args ibmi-svrmap-info.ports=2449 127.0.0.1

python3 test/mock-signon.py 2476 1 &   # sign-on server, password level 1
nmap -Pn -p 2476 --script ibmi-signon-info --script-args ibmi-signon-info.ports=2476 127.0.0.1
pkill -f mock-
```

`ibmi-hostservers` needs nothing but open ports: start a few listeners on 8470,
9470, 8475 and so on, then scan them with `-p 23,992,449,8470-8476,9470-9476`.

## Against a real system

Get permission first, and read the target's acceptable-use terms. A hosted
public system like PUB400 is run by volunteers, so keep it to one connection
at a time and slow. Swap `pub400.com` for your own target.

1. **See what is open first, no scripts, gentle**
   ```bash
   nmap -Pn -T2 --max-parallelism 1 --scan-delay 1s -p 23,992,449,8470-8476,9470-9476 pub400.com
   ```
   `-Pn` skips host discovery, `-T2` and `--scan-delay 1s` slow it down,
   `--max-parallelism 1` keeps it to one probe at a time.

2. **The sign-on screen (run this one first)**
   ```bash
   nmap -Pn -p 23 --script tn5250-info --script-args tn5250-info.dump=true pub400.com
   ```
   Keep everything it prints, especially `rawRecords`. If it errors, add `-d`
   and keep the trace too.

3. **TLS telnet on 992**
   ```bash
   nmap -Pn -p 992 --script tn5250-info,ssl-cert,ssl-enum-ciphers --script-args tn5250-info.dump=true pub400.com
   ```
   The two `ssl-` scripts are nmap's own and cover the certificate and ciphers.

4. **Port mapper on 449**
   ```bash
   nmap -Pn -p 449 --script ibmi-svrmap-info --script-args ibmi-svrmap-info.dump=true pub400.com
   ```

5. **Sign-on server (may be filtered on a hosted box)**
   ```bash
   nmap -Pn -p 8476,9476 --script ibmi-signon-info --script-args ibmi-signon-info.dump=true pub400.com
   ```

6. **The exposure summary**
   ```bash
   nmap -Pn -T2 -p 23,992,449,8470-8476,9470-9476 --script ibmi-hostservers pub400.com
   ```

7. **Everything at once, saved for a report**
   ```bash
   nmap -Pn -T2 -p 23,992,449,8470-8476,9470-9476 \
     --script "tn5250-info,ibmi-svrmap-info,ibmi-signon-info,ibmi-hostservers,ssl-cert" \
     --script-args "tn5250-info.dump=true,ibmi-svrmap-info.dump=true,ibmi-signon-info.dump=true" \
     -oA pub400-recon pub400.com
   ```
   `-oA` writes `.nmap`, `.xml` and `.gnmap` files. The XML is the part that
   goes into findings.

**Debug switches when something fails**

- `-d` or `-d2`: the script debug lines, including every byte exchange the
  scripts log.
- `--script-trace`: every packet nmap sends and receives.
- `--reason`: why a port was marked open, closed or filtered.

When a run shows something new, save the raw record into `fixtures/` and add a
line for it here.

## Where each script stands

| Script | Live system | Fixture |
|---|---|---|
| tn5250-info | PUB400, ports 23 and 992 | `pub400-23-signon-record.hex` |
| ibmi-svrmap-info | PUB400, port 449 | none yet |
| ibmi-signon-info | PUB400, ports 8476 and 9476 | none (the dump leaves out the server seed, so the mock is shaped after it) |
| ibmi-hostservers | PUB400, all 17 ports | none, reads port states only |

Full byte layouts and their confidence levels: `docs/WIRE-NOTES.md`.
