---
-- TN5250 negotiation and sign-on screen reader for Nmap NSE.
--
-- Speaks just enough of RFC 1205 (5250 over telnet) and RFC 4777 (IBM's
-- NEW-ENVIRON enhancements) to get an IBM i telnet server to show its sign-on
-- screen, then reads that screen into a text grid. It sends NO user ID and NO
-- password, ever, and does not press any key. See ../docs/SCOPE.md.
--
-- STATUS: written from the RFCs and from memory of the 5250 data stream, NOT
-- yet checked against a real IBM i. Spots that depend on a layout I am not
-- certain of are marked UNVERIFIED. Test against PUB400 or a capture before
-- trusting any of it. See ../ROADMAP.md.
--
-- @author Britley Hoff
-- @license Same as the parent repo (GPLv3) - see LICENSE

local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local table = require "table"
local mfebcdic = require "mfebcdic"

local mf5250 = {}

-- ── Telnet command bytes ────────────────────────────────────────────────
local IAC  = 0xFF
local DONT = 0xFE
local DO_  = 0xFD
local WONT = 0xFC
local WILL = 0xFB
local SB   = 0xFA
local SE   = 0xF0
local EOR  = 0xEF

-- ── Telnet options ──────────────────────────────────────────────────────
local OPT_BINARY = 0x00
local OPT_TTYPE  = 0x18
local OPT_EOR    = 0x19
local OPT_NEWENV = 0x27 -- 39, RFC 1572

local OPT_NAMES = {
  [OPT_BINARY] = "BINARY", [OPT_TTYPE] = "TERMINAL-TYPE",
  [OPT_EOR] = "END-OF-RECORD", [OPT_NEWENV] = "NEW-ENVIRON",
}
local CMD_NAMES = { [DO_] = "DO", [DONT] = "DONT", [WILL] = "WILL", [WONT] = "WONT" }

local TTYPE_IS, TTYPE_SEND = 0x00, 0x01
local NE_IS, NE_SEND = 0x00, 0x01
local NE_VAR, NE_VALUE, NE_ESC, NE_USERVAR = 0x00, 0x01, 0x02, 0x03

-- ── 5250 data stream bytes ──────────────────────────────────────────────
local ESC = 0x04 -- start of a 5250 command inside a record

local CMD_CLEAR_UNIT     = 0x40
local CMD_CLEAR_UNIT_ALT = 0x20 -- 1 parameter byte
local CMD_CLEAR_FMT      = 0x50
local CMD_WTD            = 0x11 -- Write To Display: CC1 CC2 then orders
local CMD_WSF            = 0xF3 -- Write Structured Field

local ORD_SOH = 0x01
local ORD_RA  = 0x02
local ORD_EA  = 0x03
local ORD_TD  = 0x10
local ORD_SBA = 0x11
local ORD_WEA = 0x12
local ORD_IC  = 0x13
local ORD_MC  = 0x14
local ORD_WDSF = 0x15
local ORD_SF  = 0x1D

-- Big enough for the 27x132 wide screen; a normal 24x80 sign-on just uses
-- the top-left corner.
local ROWS, COLS = 27, 132

-- ── Screen grid ─────────────────────────────────────────────────────────

local function new_screen()
  return { cells = {}, row = 1, col = 1 }
end

local function advance(scr)
  scr.col = scr.col + 1
  if scr.col > COLS then
    scr.col = 1
    scr.row = scr.row + 1
    if scr.row > ROWS then scr.row = 1 end
  end
end

local function put(scr, ch)
  scr.cells[(scr.row - 1) * COLS + scr.col] = ch
  advance(scr)
end

local function goto_addr(scr, row, col)
  if row >= 1 and row <= ROWS and col >= 1 and col <= COLS then
    scr.row, scr.col = row, col
  end
end

--- The grid as a list of right-trimmed lines, trailing blank rows dropped.
function mf5250.screen_lines(scr)
  local lines = {}
  for r = 1, ROWS do
    local chars = {}
    for c = 1, COLS do
      chars[c] = scr.cells[(r - 1) * COLS + c] or " "
    end
    lines[r] = (table.concat(chars):gsub("%s+$", ""))
  end
  while #lines > 0 and lines[#lines] == "" do lines[#lines] = nil end
  return lines
end

-- ── Write To Display order parser ───────────────────────────────────────

-- Parse orders starting at data[i], until the end of the record or the next
-- ESC command. Returns the index to resume at. Any layout I am unsure of is
-- marked UNVERIFIED; a wrong guess there shifts everything after it, which
-- is why mf5250.scan also keeps the raw record bytes available (dump arg).
local function parse_orders(data, i, scr, notes)
  local n = #data
  local function byte(k) return string.byte(data, k) end
  while i <= n do
    local b = byte(i)
    if b == ESC then
      return i
    elseif b == ORD_SBA then
      local r, c = byte(i + 1), byte(i + 2)
      if not c then return n + 1 end
      goto_addr(scr, r, c)
      i = i + 3
    elseif b == ORD_IC or b == ORD_MC then
      i = i + (b == ORD_IC and 3 or 4) -- IC: row col. MC: type row col.
    elseif b == ORD_SOH then
      -- UNVERIFIED: assumed [SOH][len][len bytes of header]. Some references
      -- count the length byte itself in len.
      local len = byte(i + 1) or 0
      i = i + 2 + len
      notes.soh = len
    elseif b == ORD_RA then
      local tr, tc, ch = byte(i + 1), byte(i + 2), byte(i + 3)
      if not ch then return n + 1 end
      local fill = mfebcdic.char(ch) or " "
      -- Fill up to and including the target address (UNVERIFIED: inclusive).
      local target = (tr - 1) * COLS + tc
      local cur = (scr.row - 1) * COLS + scr.col
      local guard = ROWS * COLS
      while cur <= target and guard > 0 do
        put(scr, fill)
        cur = cur + 1
        guard = guard - 1
      end
      i = i + 4
    elseif b == ORD_EA then
      -- UNVERIFIED: [EA][row][col][len][len-1 attribute bytes], len counts itself.
      local len = byte(i + 3) or 1
      i = i + 4 + math.max(len - 1, 0)
    elseif b == ORD_TD then
      -- UNVERIFIED: 2-byte length (not counting itself) then that many data bytes.
      local l1, l2 = byte(i + 1), byte(i + 2)
      if not l2 then return n + 1 end
      local len = l1 * 256 + l2
      for k = i + 3, math.min(i + 2 + len, n) do
        put(scr, mfebcdic.char(byte(k)) or " ")
      end
      i = i + 3 + len
    elseif b == ORD_WEA then
      i = i + 3
    elseif b == ORD_WDSF then
      -- UNVERIFIED: 2-byte length that includes its own two bytes.
      local l1, l2 = byte(i + 1), byte(i + 2)
      if not l2 then return n + 1 end
      i = i + 1 + math.max(l1 * 256 + l2, 2)
      notes.wdsf = (notes.wdsf or 0) + 1
    elseif b == ORD_SF then
      -- [SF][FFW 2 bytes if first byte is 01xxxxxx][FCW 2 bytes each while
      -- first byte is 1xxxxxxx][attribute 001xxxxx][length 2 bytes]
      local k = i + 1
      local x = byte(k)
      if x and (x & 0xC0) == 0x40 then k = k + 2 end
      x = byte(k)
      while x and (x & 0x80) == 0x80 do
        k = k + 2
        x = byte(k)
      end
      if x and (x & 0xE0) == 0x20 then k = k + 1 end -- the attribute byte
      k = k + 2 -- field length
      put(scr, " ") -- the attribute takes one screen position
      i = k
    elseif b >= 0x20 and b <= 0x3F then
      put(scr, " ") -- a standalone display attribute takes one position
      i = i + 1
    elseif b < 0x20 then
      i = i + 1 -- an order we do not know: skip the byte and carry on
      notes.unknown_order = b
    else
      put(scr, mfebcdic.char(b) or " ")
      i = i + 1
    end
  end
  return i
end

--- Parse one 5250 record (bytes between IAC EORs, IAC IAC already undone)
-- into `scr`. Returns a table describing what was seen.
function mf5250.parse_record(rec, scr)
  local info = { gds = false, commands = {}, notes = {}, bytes = #rec }
  local start = 1
  if #rec >= 10 and string.byte(rec, 3) == 0x12 and string.byte(rec, 4) == 0xA0 then
    info.gds = true
    local vh = string.byte(rec, 7)
    info.opcode = string.byte(rec, 7 + vh - 1)
    start = 7 + vh
  end

  local i = start
  local n = #rec
  while i <= n do
    if string.byte(rec, i) ~= ESC then
      info.notes.stray = string.byte(rec, i)
      break
    end
    local cmd = string.byte(rec, i + 1)
    if not cmd then break end
    if cmd == CMD_CLEAR_UNIT then
      info.commands[#info.commands + 1] = "clear-unit"
      scr.cells, scr.row, scr.col = {}, 1, 1
      i = i + 2
    elseif cmd == CMD_CLEAR_UNIT_ALT then
      info.commands[#info.commands + 1] = "clear-unit-alt"
      scr.cells, scr.row, scr.col = {}, 1, 1
      i = i + 3
    elseif cmd == CMD_CLEAR_FMT then
      info.commands[#info.commands + 1] = "clear-format-table"
      i = i + 2
    elseif cmd == CMD_WTD then
      info.commands[#info.commands + 1] = "write-to-display"
      i = parse_orders(rec, i + 4, scr, info.notes) -- skip ESC, cmd, CC1, CC2
    elseif cmd == CMD_WSF then
      info.commands[#info.commands + 1] = "write-structured-field"
      -- Skip each structured field by its length (which counts itself).
      i = i + 2
      while i <= n and string.byte(rec, i) ~= ESC do
        local l1, l2 = string.byte(rec, i), string.byte(rec, i + 1)
        if not l2 then
          i = n + 1
          break
        end
        i = i + math.max(l1 * 256 + l2, 2)
      end
    else
      info.commands[#info.commands + 1] = string.format("unhandled-0x%02X", cmd)
      info.notes.unhandled = cmd
      break
    end
  end
  return info
end

-- ── Sign-on screen interpretation ───────────────────────────────────────

--- Pull the facts a sign-on screen gives away out of the text lines.
-- Labels on IBM i look like "System  . . . . . :   PUB400".
function mf5250.parse_signon(lines)
  local out = { messages = {}, copyright = nil }
  local text = table.concat(lines, "\n")

  local function label(name)
    for _, line in ipairs(lines) do
      local v = line:match(name .. "[%s%.]*:%s*([%w#@$_%-]+)")
      if v then return v end
    end
  end
  out.system = label("System")
  out.subsystem = label("Subsystem")
  out.display = label("Display")

  local has_user = text:find("User%s+%.") ~= nil or text:find("User%s*:") ~= nil
  local has_pass = text:find("Password%s+%.") ~= nil or text:find("Password%s*:") ~= nil
  out.hasPrompt = has_user and has_pass
  out.titled = text:find("Sign On", 1, true) ~= nil

  for _, line in ipairs(lines) do
    if not out.copyright and line:upper():find("COPYRIGHT", 1, true) then
      out.copyright = (line:gsub("^%s+", ""))
    end
    local msg = line:match("(CP[FDA]%d%d%d%d.*)")
    if msg and #out.messages < 3 then
      out.messages[#out.messages + 1] = msg:sub(1, 100)
    end
  end

  out.isSignon = out.hasPrompt or (out.titled and out.system ~= nil)
  return out
end

-- ── Telnet-level reader ─────────────────────────────────────────────────

local function esc_ne(s)
  return (s:gsub("[\0-\3\255]", function(c) return "\2" .. c end))
end

local function build_newenv_is(vars)
  local parts = { string.char(IAC, SB, OPT_NEWENV, NE_IS) }
  for _, kv in ipairs(vars) do
    parts[#parts + 1] = string.char(NE_USERVAR) .. esc_ne(kv[1]) ..
      string.char(NE_VALUE) .. esc_ne(kv[2])
  end
  parts[#parts + 1] = string.char(IAC, SE)
  return table.concat(parts)
end

--- Negotiate on an already-connected socket and read records until one yields
-- screen text.
--
-- @param sock connected nmap socket (plain or TLS, the caller decides)
-- @param opts { termtype = "IBM-3179-2", devname = nil, timeout = 8000, max_records = 6 }
-- @return status (bool), result table (always a table), error string on failure
function mf5250.negotiate(sock, opts)
  opts = opts or {}
  sock:set_timeout(opts.timeout or 8000)
  local termtype = opts.termtype or "IBM-3179-2"
  local max_records = opts.max_records or 6

  local result = {
    termtype = termtype,
    devnameRequested = opts.devname,
    offered = {},      -- "DO TERMINAL-TYPE" style strings, in order seen
    envRequested = {}, -- NEW-ENVIRON variables we answered with
    records = {},      -- raw record bytes, for the dump arg
    recordInfo = {},
    log = {},
    screen = new_screen(),
  }
  local function log(dir, note)
    result.log[#result.log + 1] = dir .. ": " .. note
    stdnse.debug2("tn5250: %s: %s", dir, note)
  end

  local sent = {}
  local answered = { ttype = 0, newenv = 0 }
  local buf, rec = "", {}
  local got_text = false

  local function fetch()
    local status, data = sock:receive_bytes(1)
    if not status then return false end
    log("recv", "raw " .. #data .. " bytes: " .. stdnse.tohex(string.sub(data, 1, 48)) ..
      (#data > 48 and "..." or ""))
    buf = buf .. data
    return true
  end

  local function reply_once(cmd, opt)
    local key = cmd .. ":" .. opt
    if sent[key] then return end
    sent[key] = true
    sock:send(string.char(IAC, cmd, opt))
    log("sent", string.format("IAC %s %s", CMD_NAMES[cmd], OPT_NAMES[opt] or opt))
  end

  local function handle_subneg(sub)
    local opt, op = string.byte(sub, 1), string.byte(sub, 2)
    if opt == OPT_TTYPE and op == TTYPE_SEND and answered.ttype < 3 then
      answered.ttype = answered.ttype + 1
      sock:send(string.char(IAC, SB, OPT_TTYPE, TTYPE_IS) .. termtype .. string.char(IAC, SE))
      log("sent", "TERMINAL-TYPE IS " .. termtype)
    elseif opt == OPT_NEWENV and op == NE_SEND and answered.newenv < 3 then
      answered.newenv = answered.newenv + 1
      -- Plain US-English display. No USER, no IBMRSEED, no IBMSUBSPW: those
      -- are the auto-sign-on variables and we must never send them.
      local vars = {
        { "KBDTYPE", "USB" }, { "CODEPAGE", "37" }, { "CHARSET", "697" },
      }
      if opts.devname then
        table.insert(vars, 1, { "DEVNAME", opts.devname })
      end
      result.envRequested = {}
      for _, kv in ipairs(vars) do
        result.envRequested[#result.envRequested + 1] = kv[1] .. "=" .. kv[2]
      end
      sock:send(build_newenv_is(vars))
      log("sent", "NEW-ENVIRON IS " .. table.concat(result.envRequested, " "))
    else
      log("recv", "ignored subnegotiation, option " .. tostring(opt))
    end
  end

  local function finish_record()
    local data = table.concat(rec)
    rec = {}
    result.records[#result.records + 1] = data
    local info = mf5250.parse_record(data, result.screen)
    result.recordInfo[#result.recordInfo + 1] = info
    log("recv", string.format("record %d: %d bytes, %s%s", #result.records, #data,
      info.gds and "GDS" or "no GDS header",
      #info.commands > 0 and (", " .. table.concat(info.commands, ",")) or ""))
    local lines = mf5250.screen_lines(result.screen)
    for _, l in ipairs(lines) do
      if l:match("%a") then got_text = true break end
    end
  end

  while not got_text and #result.records < max_records do
    local i = 1
    while i <= #buf do
      local b = string.byte(buf, i)
      if b ~= IAC then
        rec[#rec + 1] = string.char(b)
        i = i + 1
      else
        if i + 1 > #buf then break end
        local cmd = string.byte(buf, i + 1)
        if cmd == IAC then
          rec[#rec + 1] = string.char(IAC)
          i = i + 2
        elseif cmd == DO_ or cmd == DONT or cmd == WILL or cmd == WONT then
          if i + 2 > #buf then break end
          local opt = string.byte(buf, i + 2)
          result.offered[#result.offered + 1] =
            CMD_NAMES[cmd] .. " " .. (OPT_NAMES[opt] or string.format("0x%02X", opt))
          if cmd == DO_ and (opt == OPT_TTYPE or opt == OPT_BINARY or
              opt == OPT_EOR or opt == OPT_NEWENV) then
            reply_once(WILL, opt)
          elseif cmd == WILL and (opt == OPT_BINARY or opt == OPT_EOR) then
            reply_once(DO_, opt)
          elseif cmd == DO_ then
            reply_once(WONT, opt)
          elseif cmd == WILL then
            reply_once(DONT, opt)
          end
          i = i + 3
        elseif cmd == SB then
          local j, se_at = i + 2, nil
          while j <= #buf - 1 do
            if string.byte(buf, j) == IAC and string.byte(buf, j + 1) == SE then
              se_at = j
              break
            end
            j = j + 1
          end
          if not se_at then break end
          handle_subneg(string.sub(buf, i + 2, se_at - 1))
          i = se_at + 2
        elseif cmd == EOR then
          finish_record()
          i = i + 2
          if got_text then break end
        else
          i = i + 2
        end
      end
    end
    buf = string.sub(buf, i)
    if got_text then break end
    if not fetch() then break end
  end

  if not got_text then
    local partial = #rec > 0 and mfebcdic.to_ascii(table.concat(rec)) or nil
    result.partialText = partial
    return false, result, "no 5250 screen received (see trace)"
  end
  return true, result
end

-- ── Shared NSE action body ──────────────────────────────────────────────

--- Connect, negotiate, read the sign-on screen, report. Shared by
-- scripts/tn5250-info.nse and any local test variant.
function mf5250.scan(host, port, opts)
  opts = opts or {}
  local sock = nmap.new_socket()
  local use_tls = (port.number == 992) or (port.service == "tn5250s") or
    (port.service == "telnets")

  local status, err
  if use_tls then
    status, err = sock:connect(host, port, "ssl")
  else
    status, err = sock:connect(host, port)
  end
  if not status then
    return stdnse.format_output(false, "could not connect: " .. tostring(err))
  end

  local ok, result, errmsg = mf5250.negotiate(sock, opts)
  sock:close()

  local out = stdnse.output_table()
  out.tls = use_tls

  if not ok then
    out.error = errmsg
    if #result.offered > 0 then out.optionsSeen = result.offered end
    if result.partialText and result.partialText:match("%S") then
      -- Text with no EOR and no 5250 framing: most likely a plain telnet
      -- service on 23, not IBM i.
      out.plainTextSeen = result.partialText:sub(1, 120)
    end
    if #result.log > 0 then out.trace = result.log end
    return out
  end

  local lines = mf5250.screen_lines(result.screen)
  local si = mf5250.parse_signon(lines)

  out.terminalType = result.termtype
  out.deviceNameRequested = result.devnameRequested or "(none, server assigns one)"
  out.optionsSeen = result.offered
  out.screenType = si.isSignon and "IBM i sign-on" or "unrecognized 5250 screen"
  if si.system then out.systemName = si.system end
  if si.subsystem then out.subsystem = si.subsystem end
  if si.display then out.displayDevice = si.display end
  if si.copyright then out.copyright = si.copyright end
  if #si.messages > 0 then out.messages = si.messages end

  local findings = {}
  if si.isSignon and not use_tls then
    findings[#findings + 1] =
      "sign-on screen served over plain telnet; user IDs and passwords would cross the network unencrypted"
  end
  if #findings > 0 then out.findings = findings end

  if opts.dump then
    out.screen = lines
    local hex = {}
    for k, r in ipairs(result.records) do
      hex[k] = stdnse.tohex(r)
    end
    out.rawRecords = hex
    out.parsed = {}
    for k, info in ipairs(result.recordInfo) do
      out.parsed[k] = string.format("record %d: %d bytes, gds=%s, commands=%s",
        k, info.bytes, tostring(info.gds), table.concat(info.commands, ","))
    end
  end

  return out
end

return mf5250
