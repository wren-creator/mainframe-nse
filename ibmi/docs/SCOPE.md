# Scope

## In

Unauthenticated, single-connect reads: banners, sign-on screens, server
versions, port mapper answers, which ports are plain or TLS.

## Out

Anything that sends credentials, runs commands, or walks a signed-on session.
IBM i locks accounts, `QSECOFR` included, after `MAXSIGN` failed attempts.
That risk is the whole reason for the line.

## Already covered by stock Nmap

TLS certificates and ciphers (`ssl-cert`, `ssl-enum-ciphers`), and DRDA
(`drda-info`). Check these before writing anything new.

## Port reference

| Port | Role |
|---|---|
| 23, 992 | Telnet and TLS telnet, 5250 sign-on |
| 449 | Server mapper, cleartext, looks up a host server port by name |
| 8470, 9470 | as-central |
| 8471, 9471 | as-database |
| 8472, 9472 | as-dtaq |
| 8473, 9473 | as-file |
| 8474, 9474 | as-netprt |
| 8475, 9475 | as-rmtcmd (hands off) |
| 8476, 9476 | as-signon |

Source: IBM i host server port table,
https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_74/rzajr/rzajrservicesandports.htm
