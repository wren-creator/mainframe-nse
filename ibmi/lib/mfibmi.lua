---
-- IBM i host server helpers for Nmap NSE: the port mapper on 449 now, the
-- sign-on server exchange later (see ROADMAP.md).
--
-- STATUS: the port mapper exchange is written from memory of how IBM's Java
-- toolbox client talks to it, NOT checked against a real IBM i. Spots that
-- depend on that memory are marked UNVERIFIED.
--
-- @author Britley Hoff
-- @license Same as the parent repo (GPLv3) - see LICENSE

local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local table = require "table"

local mfibmi = {}

--- Host servers, in the order we ask. `plain` and `secure` are the service
-- names the port mapper knows them by (UNVERIFIED); `default_*` are the
-- documented default ports, used only to flag a server that has moved.
mfibmi.SERVERS = {
  { label = "central",  plain = "as-central",  secure = "as-central-s",  default_plain = 8470, default_secure = 9470 },
  { label = "database", plain = "as-database", secure = "as-database-s", default_plain = 8471, default_secure = 9471 },
  { label = "dtaq",     plain = "as-dtaq",     secure = "as-dtaq-s",     default_plain = 8472, default_secure = 9472 },
  { label = "file",     plain = "as-file",     secure = "as-file-s",     default_plain = 8473, default_secure = 9473 },
  { label = "netprt",   plain = "as-netprt",   secure = "as-netprt-s",   default_plain = 8474, default_secure = 9474 },
  { label = "rmtcmd",   plain = "as-rmtcmd",   secure = "as-rmtcmd-s",   default_plain = 8475, default_secure = 9475 },
  { label = "signon",   plain = "as-signon",   secure = "as-signon-s",   default_plain = 8476, default_secure = 9476 },
}

--- Ask the port mapper for one service's port. One connection per name, the
-- way IBM's own client does it (UNVERIFIED: the server may allow reuse).
--
-- Request: the service name in ASCII, no terminator (UNVERIFIED).
-- Reply:   0x2B ('+') then a 4-byte big-endian port on success; anything
--          else is treated as "not known" (UNVERIFIED).
--
-- @return "port", number | "unknown", firstbyte | "error", message
function mfibmi.lookup(host, port, name, timeout)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout or 5000)
  local ok, err = sock:connect(host, port)
  if not ok then return "error", "connect: " .. tostring(err) end
  ok, err = sock:send(name)
  if not ok then
    sock:close()
    return "error", "send: " .. tostring(err)
  end
  local status, data = sock:receive_bytes(1)
  if status and #data < 5 then
    -- The reply may arrive in pieces; give it one more read.
    local s2, d2 = sock:receive_bytes(5 - #data)
    if s2 then data = data .. d2 end
  end
  sock:close()
  if not status then return "error", "no reply: " .. tostring(data) end
  local first = string.byte(data, 1)
  if first == 0x2B and #data >= 5 then
    local p = string.unpack(">I4", data, 2)
    return "port", p, data
  end
  return "unknown", first, data
end

--- Look up every host server, plain and secure.
-- @return list of { label, plainPort, securePort, notes = {}, raw = {} }, errors
function mfibmi.map_servers(host, port, opts)
  opts = opts or {}
  local rows, errors, consecutive = {}, {}, 0
  for _, srv in ipairs(mfibmi.SERVERS) do
    local row = { label = srv.label, notes = {}, raw = {} }
    for _, kind in ipairs({ "plain", "secure" }) do
      if consecutive >= 3 then break end -- the host is not answering, stop early
      local what, val, raw = mfibmi.lookup(host, port, srv[kind], opts.timeout)
      if what == "port" then
        consecutive = 0
        row[kind .. "Port"] = val
        row.raw[kind] = stdnse.tohex(raw)
        if val ~= srv["default_" .. kind] then
          row.notes[#row.notes + 1] = string.format("%s on %d, not the default %d",
            kind, val, srv["default_" .. kind])
        end
      elseif what == "unknown" then
        consecutive = 0
        row.raw[kind] = raw and stdnse.tohex(raw) or nil
      else
        consecutive = consecutive + 1
        errors[#errors + 1] = srv[kind] .. ": " .. val
      end
    end
    rows[#rows + 1] = row
  end
  return rows, errors
end

return mfibmi
