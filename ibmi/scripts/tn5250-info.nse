local shortport = require "shortport"
local stdnse = require "stdnse"
local mf5250 = require "mf5250"

description = [[
Connects to a TN5250 service (the terminal protocol behind IBM i, formerly
AS/400 or iSeries, sign-on screens), completes the RFC 1205 / RFC 4777 telnet
negotiation, and reads the sign-on screen the server shows before anyone
logs in. Reports the system name, the subsystem, the display device the
server assigned, the copyright line (which hints at the OS release), any
CPF/CPD message on the screen, and whether the sign-on was served over plain
telnet or TLS.

Nmap has no built-in TN5250 support, so a plain version scan of port 23 or
992 on an IBM i reports only an open port or a generic telnet banner.

This script does NOT report TLS certificate or cipher details for port 992.
Nmap's ssl-cert and ssl-enum-ciphers already do that, run them alongside.

SAFETY: sends no user ID and no password, presses no keys, and does not send
the auto-sign-on environment variables (USER, IBMRSEED, IBMSUBSPW). By
default it also sends no device name, so the server assigns an ordinary
QPADEV virtual device and nothing new is created on the system. IBM i locks
profiles after repeated failed sign-ons, so this script never attempts one.

STATUS: written from the RFCs, not yet verified against a real IBM i.
]]

---
-- @usage
-- nmap --script tn5250-info -p 23,992 <target>
-- nmap --script tn5250-info --script-args tn5250-info.ports=2323 -p 2323 <target>
-- nmap --script tn5250-info --script-args tn5250-info.dump=true -p 23 <target>
--
-- @args tn5250-info.ports Comma-separated extra TCP ports to treat as TN5250.
-- @args tn5250-info.devname Ask for this device name. Off by default: on an
--       IBM i with auto-create on, naming a device can create a new device
--       description on the system.
-- @args tn5250-info.termtype Terminal type to announce. Default IBM-3179-2
--       (24x80 color display).
-- @args tn5250-info.dump Set to true to include the screen text and the raw
--       record bytes in the output, for bug reports and for building test
--       captures.
--
-- @output
-- PORT   STATE SERVICE
-- 23/tcp open  telnet
-- | tn5250-info:
-- |   tls: false
-- |   terminalType: IBM-3179-2
-- |   deviceNameRequested: (none, server assigns one)
-- |   screenType: IBM i sign-on
-- |   systemName: EXAMPLE1
-- |   subsystem: QINTER
-- |   displayDevice: QPADEV0003
-- |   findings:
-- |_    sign-on screen served over plain telnet; user IDs and passwords would cross the network unencrypted

author = "Britley Hoff"
license = "Same as the parent repo (GPLv3) - see LICENSE"
categories = { "discovery", "safe" }

local default_rule = shortport.port_or_service({ 23, 992 }, { "tn5250", "tn5250s" }, "tcp")

local extra_ports = {}
local arg_ports = stdnse.get_script_args("tn5250-info.ports")
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
  return mf5250.scan(host, port, {
    devname = stdnse.get_script_args("tn5250-info.devname"),
    termtype = stdnse.get_script_args("tn5250-info.termtype"),
    dump = stdnse.get_script_args("tn5250-info.dump") == "true",
  })
end
