local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
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

portrule = shortport.port_or_service({ 23, 992 }, { "tn3270", "tn3270s" }, "tcp")

action = function(host, port)
  local sock = nmap.new_socket()
  local use_tls = (port.number == 992) or (port.service == "tn3270s")

  local status, err
  if use_tls then
    status, err = sock:connect(host, port, "ssl")
  else
    status, err = sock:connect(host, port)
  end
  if not status then
    return stdnse.format_output(false, "could not connect: " .. tostring(err))
  end

  local ok, result = tn3270.negotiate(sock, { model = "3278-2" })
  sock:close()

  if not ok then
    return stdnse.format_output(false, tostring(result))
  end

  local out = stdnse.output_table()
  out.tn3270e = result.tn3270e
  out.deviceType = result.deviceType or "(classic TN3270, no TN3270E)"
  out.luRequested = result.luRequested or "(none requested)"
  out.luGranted = result.luGranted or "(none)"
  if result.rejected then
    out.deviceTypeRejected = result.rejectReason
  end

  if result.screenText and result.screenText:match("%S") then
    out.hostType = tn3270.classify_host(result.screenText)
    local esm = tn3270.classify_esm(result.screenText)
    if esm.product ~= "unknown" then
      out.securityManager = string.format("%s (%d%% confidence%s)",
        esm.product, math.floor(esm.confidence * 100 + 0.5),
        esm.runnerUp and (", vs " .. esm.runnerUp) or "")
      if #esm.evidence > 0 then
        out.evidence = esm.evidence[1].matched
      end
    end
  else
    out.hostType = "unknown (no screen text read)"
  end

  return out
end
