local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local mfibmi = require "mfibmi"

description = [[
Talks to the IBM i sign-on server (as-signon, 8476 plain or 9476 TLS) and
does the exchange-attributes step every IBM i client does before it signs on.
The server answers with its OS version (V7R4M0 style), its datastream level,
its password level (the QPWDLVL system value), and the name of the server
job that answered, all without a user ID or password.

The password level is the useful finding for a security review. Levels 0 and
1 limit passwords to 10 characters and keep older, weaker storage forms.

SAFETY: sends no user ID and no password, and never starts a sign-on. The
server seed in the reply is not printed. Does not touch any other host
server.

STATUS: checked against a live IBM i 7.5 (PUB400), plain and TLS.
]]

---
-- @usage
-- nmap --script ibmi-signon-info -p 8476,9476 <target>
-- nmap --script ibmi-signon-info --script-args ibmi-signon-info.dump=true -p 8476 <target>
--
-- @args ibmi-signon-info.ports Extra TCP ports to treat as the sign-on server.
-- @args ibmi-signon-info.tls Set to true to use TLS on those extra ports.
-- @args ibmi-signon-info.dump Set to true to include the reply code points
--       and raw bytes.
--
-- @output
-- PORT     STATE SERVICE
-- 8476/tcp open  as-signon
-- | ibmi-signon-info:
-- |   tls: false
-- |   osVersion: V7R4M0
-- |   datastreamLevel: 5
-- |   passwordLevel: 3 (passphrases up to 128 characters, no old-style hashes kept)
-- |_  serverJob: 135258/QUSER/QZSOSIGN

author = "Britley Hoff"
license = "Same as the parent repo (GPLv3) - see LICENSE"
categories = { "discovery", "safe" }

local default_rule = shortport.port_or_service({ 8476, 9476 }, { "as-signon", "as-signon-s" }, "tcp")

local extra_ports = {}
local arg_ports = stdnse.get_script_args("ibmi-signon-info.ports")
if arg_ports then
  for p in tostring(arg_ports):gmatch("%d+") do
    extra_ports[#extra_ports + 1] = tonumber(p)
  end
end
local extra_rule = #extra_ports > 0 and shortport.portnumber(extra_ports, "tcp") or nil

portrule = function(host, port)
  return default_rule(host, port) or (extra_rule ~= nil and extra_rule(host, port))
end

action = function(host, port)
  local use_tls = port.number == 9476 or port.service == "as-signon-s" or
    stdnse.get_script_args("ibmi-signon-info.tls") == "true"
  local dump = stdnse.get_script_args("ibmi-signon-info.dump") == "true"

  local r, err, raw = mfibmi.signon_exchange(host, port, use_tls)
  local out = stdnse.output_table()
  out.tls = use_tls
  if not r then
    out.error = err
    if raw then out.rawReply = stdnse.tohex(raw) end
    return out
  end

  if r.version then out.osVersion = r.version end
  if r.level then out.datastreamLevel = r.level end
  if r.passwordLevelText then out.passwordLevel = r.passwordLevelText end
  if r.serverJob then out.serverJob = r.serverJob end
  if r.ccsid then out.ccsid = r.ccsid end
  if r.returnCode and r.returnCode ~= 0 then
    out.returnCode = string.format("0x%08X", r.returnCode)
  end
  if not (r.version or r.passwordLevelText) then
    out.note = "reply parsed but held no version or password level, rerun with ibmi-signon-info.dump=true"
  end

  local findings = {}
  if r.passwordLevel and r.passwordLevel < 2 then
    findings[#findings + 1] = string.format(
      "password level %d: passwords limited to 10 characters with older storage forms", r.passwordLevel)
  end
  if not use_tls then
    findings[#findings + 1] = "sign-on server reachable in plain text on this port"
  end
  if #findings > 0 then out.findings = findings end

  if dump then
    local cps = {}
    for _, e in ipairs(r.llcps) do
      if e.cp == 0x1103 then
        cps[#cps + 1] = string.format("0x%04X (%d bytes, not shown)", e.cp, #e.data)
      else
        cps[#cps + 1] = string.format("0x%04X = %s", e.cp, stdnse.tohex(e.data))
      end
    end
    out.codePoints = cps
    out.header = string.format("serverId=0x%04X replyId=0x%04X templateLength=%d",
      r.serverId, r.replyId, r.templateLength)
    -- raw bytes include the seed, so only keep them for failures
  end
  return out
end
