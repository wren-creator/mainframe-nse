---
-- IBM i host server helpers for Nmap NSE: the port mapper on 449 now, the
-- sign-on server exchange later (see ROADMAP.md).
--
-- STATUS: the port mapper exchange was checked against a live IBM i 7.5
-- (PUB400). The sign-on server exchange further down is still written from
-- memory and NOT checked against a real system. Spots that depend on that
-- memory are marked UNVERIFIED.
--
-- @author Britley Hoff
-- @license Same as the parent repo (GPLv3) - see LICENSE

local stdnse = require "stdnse"
local rand = require "rand"
local mfebcdic = require "mfebcdic"
local nmap = require "nmap"
local string = require "string"
local table = require "table"

local mfibmi = {}

--- Host servers, in the order we ask. `plain` and `secure` are the service
-- names the port mapper knows them by (confirmed on PUB400); `default_*` are the
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
-- way IBM's own client does it. Reuse of one connection is untested.
--
-- Request: the service name in ASCII, no terminator (confirmed).
-- Reply:   0x2B ('+') then a 4-byte big-endian port on success (confirmed);
--          anything else is treated as "not known" (that reply is UNVERIFIED).
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

-- ── Sign-on server (as-signon, 8476 plain / 9476 TLS) ──────────────────

-- Password level meanings, QPWDLVL. 0 and 1 are the old DES-era levels with
-- 10 character passwords, 2 and 3 allow long passphrases. Anything else is
-- reported as the raw number.
local PWDLVL_TEXT = {
  [0] = "0 (passwords up to 10 characters, DES-era storage)",
  [1] = "1 (passwords up to 10 characters, DES-era storage)",
  [2] = "2 (passphrases up to 128 characters)",
  [3] = "3 (passphrases up to 128 characters, no old-style hashes kept)",
}

local function llcp(cp, data)
  return string.pack(">I4I2", #data + 6, cp) .. data
end

--- Build the exchange-attributes request: a 20 byte header (length, header
-- id 0, server id 0xE009, two zero 4-byte fields, template length 0, request
-- id 0x7003) then three LLCPs: client version, client datastream level and a
-- client seed. Accepted by PUB400, so the request layout is confirmed.
function mfibmi.build_signon_request()
  local body = llcp(0x1101, string.pack(">I4", 1)) ..
    llcp(0x1102, string.pack(">I2", 2)) ..
    llcp(0x1103, rand.random_string(8))
  local header = string.pack(">I4I2I2I4I4I2I2", 20 + #body, 0, 0xE009, 0, 0, 0, 0x7003)
  return header .. body
end

--- Read one length-prefixed reply (the first 4 bytes are the total length).
local function read_reply(sock)
  local status, data = sock:receive_bytes(4)
  if not status then return nil, "no reply: " .. tostring(data) end
  local want = string.unpack(">I4", data)
  if want < 20 or want > 65536 then
    return nil, string.format("implausible reply length %d", want), data
  end
  while #data < want do
    local s, more = sock:receive_bytes(want - #data)
    if not s then break end
    data = data .. more
  end
  return data
end

--- Parse the reply header, template and LLCPs.
-- Confirmed on PUB400 (7.5): server id 0xE009, reply id 0xF003 (not F004 as
-- first assumed), a 4 byte return code in the template, and code points
-- 0x1101 server version, 0x1102 datastream level, 0x1103 server seed,
-- 0x1119 password level, 0x111F server job name. 0x1114 (CCSID) was in the
-- first draft and PUB400 does not send it.
function mfibmi.parse_signon_reply(data)
  local r = { llcps = {} }
  if #data < 20 then return nil, "reply shorter than a header" end
  local len, _, server_id = string.unpack(">I4I2I2", data)
  r.length, r.serverId = len, server_id
  local tmpl, req_id = string.unpack(">I2I2", data, 17)
  r.replyId = req_id
  r.templateLength = tmpl
  if tmpl >= 4 and #data >= 24 then
    r.returnCode = string.unpack(">I4", data, 21)
  end
  local pos = 21 + tmpl
  while pos + 5 <= #data do
    local l, cp = string.unpack(">I4I2", data, pos)
    if l < 6 or pos + l - 1 > #data then break end
    r.llcps[#r.llcps + 1] = { cp = cp, data = string.sub(data, pos + 6, pos + l - 1) }
    pos = pos + l
  end
  for _, e in ipairs(r.llcps) do
    if e.cp == 0x1101 and #e.data == 4 then
      local v = string.unpack(">I4", e.data)
      r.version = string.format("V%dR%dM%d", (v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF)
    elseif e.cp == 0x1102 and #e.data == 2 then
      r.level = string.unpack(">I2", e.data)
    elseif e.cp == 0x1103 then
      r.hasSeed = true -- never reported, it is a one-time value for password encryption
    elseif e.cp == 0x1114 and #e.data == 4 then
      r.ccsid = string.unpack(">I4", e.data) -- not sent by PUB400 (7.5), UNVERIFIED
    elseif e.cp == 0x111F and #e.data > 4 then
      -- Confirmed on PUB400: 4 bytes (all zero there) then the server job
      -- name in EBCDIC as "number/user/name", e.g. 135258/QUSER/QZSOSIGN.
      r.serverJob = mfebcdic.to_ascii(string.sub(e.data, 5))
    elseif e.cp == 0x1119 and #e.data == 1 then
      r.passwordLevel = string.byte(e.data)
      r.passwordLevelText = PWDLVL_TEXT[r.passwordLevel] or
        string.format("%d (not a level this script knows)", r.passwordLevel)
    end
  end
  return r
end

--- Connect, send the exchange-attributes request, parse the reply.
-- No user, no password: this is the step every client does before it signs on.
function mfibmi.signon_exchange(host, port, use_tls, timeout)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout or 6000)
  local ok, err
  if use_tls then ok, err = sock:connect(host, port, "ssl") else ok, err = sock:connect(host, port) end
  if not ok then return nil, "connect: " .. tostring(err) end
  ok, err = sock:send(mfibmi.build_signon_request())
  if not ok then
    sock:close()
    return nil, "send: " .. tostring(err)
  end
  local data, rerr, partial = read_reply(sock)
  sock:close()
  if not data then return nil, rerr, partial end
  local parsed, perr = mfibmi.parse_signon_reply(data)
  if not parsed then return nil, perr, data end
  return parsed, nil, data
end

return mfibmi
