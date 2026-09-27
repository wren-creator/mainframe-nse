local shortport = require "shortport"
local tn3270 = require "tn3270"

description = [[
Connects to a TN3270E service (the terminal protocol behind IBM mainframe
z/OS, z/VM, and CICS sessions) and performs the RFC 2355 TN3270E
device-type/functions sub-negotiation, then reads the first screen to
classify the host application (TSO, z/VM CMS, CICS, ISPF, SDSF, IMS, or a
bare logon panel) and, where a logon or error screen names one, the
external security manager guarding it (RACF, ACF2, or Top Secret).

Nmap has no built-in TN3270/TN3270E protocol support, so a plain
version-detection scan against port 23 or 992 on a mainframe reports only
an open port. This script adds the negotiation and banner-classification
layer that's missing.

This script does NOT report TLS cipher suite or certificate details for
TLS-wrapped TN3270E (port 992) -- Nmap's own ssl-cert and ssl-enum-ciphers
scripts already do that; run them alongside this one for the full picture.

Only reads what the host offers during normal protocol negotiation and the
first unsolicited screen. Sends no credentials and no AID keys.
]]

---
-- @usage
-- nmap --script tn3270-info -p 23,992 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 23/tcp  open  tn3270
-- | tn3270-info:
-- |   tn3270e: true
-- |   deviceType: IBM-3278-2
-- |   luRequested: (none requested)
-- |   luGranted: (none)
-- |   hostType: TSO
-- |   securityManager: RACF (92% confidence)
-- |_  evidence: ICH70001I LAST ACCESS AT 09:14:0

author = "Britley Hoff"
license = "Same as the parent repo (GPLv3) - see LICENSE"
categories = { "discovery", "safe" }

-- Real TN3270E ports only. For local testing against web3270's mock LPARs
-- (which default to non-privileged ports 3270/3271), use
-- test/tn3270-info-local.nse instead of editing this list -- see
-- test/README.md.
portrule = shortport.port_or_service({ 23, 992 }, { "tn3270", "tn3270s" }, "tcp")

action = function(host, port)
  return tn3270.scan(host, port)
end
