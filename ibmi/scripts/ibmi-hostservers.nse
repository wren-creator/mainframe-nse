local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local mfibmi = require "mfibmi"

description = [[
Summarizes how an IBM i exposes its host servers, using only the port states
Nmap already found. It makes no connections of its own, so it never touches
the remote command server or any other host server.

Scan the ports first, for example:
  nmap -p 23,992,449,8470-8476,9470-9476 --script ibmi-hostservers <target>

For each host server (central, database, data queue, file, network print,
remote command, sign-on) it reports the plain port and the TLS port states,
and flags:
  * a server open in plain text whose TLS port is not open
  * the remote command server reachable at all
  * plain telnet (23) open with TLS telnet (992) not open

IBM's own hardening guidance is to offer TLS only. This is the quick view of
how far a box is from that.

Runs only when at least one of those ports is open. Ports that were not
scanned show as "not scanned", which is not the same as closed.
]]

---
-- @usage
-- nmap -p 23,992,449,8470-8476,9470-9476 --script ibmi-hostservers <target>
--
-- @output
-- Host script results:
-- | ibmi-hostservers:
-- |   as-central: plain open (8470), TLS open (9470)
-- |   as-rmtcmd: plain open (8475), TLS closed (9475)
-- |   telnet: plain open (23), TLS closed (992)
-- |   findings:
-- |     as-rmtcmd open in plain text on 8475 and TLS 9475 is closed
-- |_    as-rmtcmd (remote command server) is reachable, limit it to trusted networks

author = "Britley Hoff"
license = "Same as the parent repo (GPLv3) - see LICENSE"
categories = { "discovery", "safe" }

local function state_of(host, number)
  local p = nmap.get_port_state(host, { number = number, protocol = "tcp" })
  return p and p.state or nil
end

local function describe(state, number)
  return string.format("%s (%d)", state or "not scanned", number)
end

hostrule = function(host)
  local numbers = { 23, 992 }
  for _, s in ipairs(mfibmi.SERVERS) do
    numbers[#numbers + 1] = s.default_plain
    numbers[#numbers + 1] = s.default_secure
  end
  for _, n in ipairs(numbers) do
    local st = state_of(host, n)
    -- 449 alone does not count: it is also the trigger for ibmi-svrmap-info
    if st == "open" then return true end
  end
  return false
end

action = function(host)
  local out = stdnse.output_table()
  local findings = {}

  for _, s in ipairs(mfibmi.SERVERS) do
    local plain = state_of(host, s.default_plain)
    local tls = state_of(host, s.default_secure)
    if plain == "open" or tls == "open" then
      out["as-" .. s.label] = string.format("plain %s, TLS %s",
        describe(plain, s.default_plain), describe(tls, s.default_secure))
    end
    if plain == "open" and tls ~= "open" then
      findings[#findings + 1] = string.format("as-%s open in plain text on %d and TLS %d is %s",
        s.label, s.default_plain, s.default_secure, tls or "not scanned")
    end
    if s.label == "rmtcmd" and (plain == "open" or tls == "open") then
      findings[#findings + 1] =
        "as-rmtcmd (remote command server) is reachable, limit it to trusted networks"
    end
  end

  local t23, t992 = state_of(host, 23), state_of(host, 992)
  if t23 == "open" or t992 == "open" then
    out.telnet = string.format("plain %s, TLS %s", describe(t23, 23), describe(t992, 992))
    if t23 == "open" and t992 ~= "open" then
      findings[#findings + 1] = "plain telnet (23) is open and TLS telnet (992) is " ..
        (t992 or "not scanned")
    end
  end

  local s449 = state_of(host, 449)
  if s449 then out.serverMapper = describe(s449, 449) end

  if #findings > 0 then out.findings = findings end
  return out
end
