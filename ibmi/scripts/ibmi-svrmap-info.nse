local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local mfibmi = require "mfibmi"

description = [[
Asks the IBM i server mapper (port 449, as-svrmap) which ports the host
servers are listening on: central, database, data queue, file, network print,
remote command, and sign-on, each in plain and TLS form. The mapper answers
without any sign-on.

Nmap labels 8470 to 8474 with unrelated names (cisco-avp, otv and so on), so
a plain scan gives no hint that an IBM i is there. This script reports what
the box itself says, and flags servers that moved off their default ports
and servers that are offered in plain text with no TLS twin.

Only asks for port numbers. It does not connect to any host server it finds,
and it never touches the remote command server (as-rmtcmd) beyond naming its
port.

STATUS: checked against a live IBM i 7.5 (PUB400).
]]

---
-- @usage
-- nmap --script ibmi-svrmap-info -p 449 <target>
-- nmap --script ibmi-svrmap-info --script-args ibmi-svrmap-info.dump=true -p 449 <target>
--
-- @args ibmi-svrmap-info.dump Set to true to include the raw reply bytes.
--
-- @output
-- PORT    STATE SERVICE
-- 449/tcp open  as-servermap
-- | ibmi-svrmap-info:
-- |   as-central: plain 8470, TLS 9470
-- |   as-database: plain 8471, TLS 9471
-- |   as-signon: plain 8476, TLS 9476
-- |   findings:
-- |_    as-rmtcmd offered in plain text on 8475 (remote command server)

author = "Britley Hoff"
license = "Same as the parent repo (GPLv3) - see LICENSE"
categories = { "discovery", "safe" }

local default_rule = shortport.port_or_service(449, "as-servermap", "tcp")

local extra_ports = {}
local arg_ports = stdnse.get_script_args("ibmi-svrmap-info.ports")
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
  local rows, errors = mfibmi.map_servers(host, port)
  local dump = stdnse.get_script_args("ibmi-svrmap-info.dump") == "true"
  local out = stdnse.output_table()
  local findings, answered = {}, 0

  for _, row in ipairs(rows) do
    local plain = row.plainPort and ("plain " .. row.plainPort) or "plain none"
    local tls = row.securePort and ("TLS " .. row.securePort) or "TLS none"
    if row.plainPort or row.securePort then
      answered = answered + 1
      local line = plain .. ", " .. tls
      if #row.notes > 0 then line = line .. " (" .. table.concat(row.notes, "; ") .. ")" end
      out["as-" .. row.label] = line
      if row.plainPort and not row.securePort then
        findings[#findings + 1] = string.format("as-%s offered in plain text on %d with no TLS twin",
          row.label, row.plainPort)
      end
    end
  end

  if answered == 0 then
    out.error = "the server mapper gave no usable answer"
    if #errors > 0 then out.errors = errors end
    return out
  end
  if #findings > 0 then out.findings = findings end
  if #errors > 0 then out.errors = errors end
  if dump then
    local raw = {}
    for _, row in ipairs(rows) do
      for kind, hex in pairs(row.raw) do
        raw[#raw + 1] = string.format("as-%s %s: %s", row.label, kind, hex)
      end
    end
    out.rawReplies = raw
  end
  return out
end
