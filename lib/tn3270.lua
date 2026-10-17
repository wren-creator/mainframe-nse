---
-- TN3270E negotiation-layer library for Nmap NSE.
--
-- Implements just enough of RFC 1576 (TN3270) / RFC 2355 (TN3270E) telnet
-- option negotiation to identify a TN3270E host: DEVICE-TYPE and FUNCTIONS
-- sub-negotiation, plus a minimal 3270-order-aware EBCDIC text extractor for
-- reading the first screen's banner text. This is NOT a full field/screen
-- model -- see docs/NEGOTIATION-NOTES.md and docs/FEASIBILITY.md in the
-- parent repo for why that's out of scope for a v1 NSE script.
--
-- Cross-checked against (not ported from) web3270's
-- Bridge_server/tn3270/session.js, which negotiates the server side of this
-- same exchange, and Bridge_server/tn3270/ebcdic.js for the CP037 table.
--
-- @author Britley Hoff
-- @license Same as the parent repo (GPLv3) - see LICENSE

local stdnse = require "stdnse"
local nmap = require "nmap"

local tn3270 = {}

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
local OPT_BINARY  = 0x00
local OPT_TTYPE   = 0x18
local TTYPE_IS    = 0x00 -- RFC 1091 TERMINAL-TYPE subnegotiation: IS / SEND
local TTYPE_SEND  = 0x01
local OPT_EOR     = 0x19
local OPT_TN3270E = 0x28

-- ── TN3270E sub-option function codes ──────────────────────────────────
local TN3E_CONNECT     = 0x01
local TN3E_DEVICE_TYPE = 0x02
local TN3E_FUNCTIONS   = 0x03
local TN3E_IS          = 0x04
local TN3E_REJECT      = 0x06
local TN3E_REQUEST     = 0x07
local TN3E_SEND        = 0x08

local TN3E_REASON_NAMES = {
  [0x00] = "CONN-PARTNER",    [0x01] = "DEVICE-IN-USE",
  [0x02] = "INV-ASSOCIATE",   [0x03] = "INV-NAME",
  [0x04] = "INV-DEVICE-TYPE", [0x05] = "TYPE-NAME-ERROR",
  [0x06] = "UNKNOWN-ERROR",   [0x07] = "UNSUPPORTED-REQ",
}

-- FUNCTIONS capability codes (a separate byte-value space from the
-- sub-option codes above). v1 only ever requests DATA-STREAM-CTL; it does
-- not implement RESPONSES (would require sending RESPONSE data-type
-- records back), BIND-IMAGE, SCS-CTL-CODES, or SYSREQ handling.
local TN3E_FN_DATA_STREAM_CTL = 0x01

-- ── 3270 orders (v1: enough to skip parameter bytes, not a full decoder) ─
local ORDER_SF  = 0x1D  -- Start Field:            1 param byte
local ORDER_SFE = 0x29  -- Start Field Extended:   1 + 2*count
local ORDER_SBA = 0x11  -- Set Buffer Address:     2
local ORDER_SA  = 0x28  -- Set Attribute:          2
local ORDER_MF  = 0x2C  -- Modify Field:           1 + 2*count
local ORDER_IC  = 0x13  -- Insert Cursor:          0
local ORDER_PT  = 0x05  -- Program Tab:            0
local ORDER_RA  = 0x3C  -- Repeat to Address:      3
local ORDER_EUA = 0x12  -- Erase Unprotected:      2

-- ── CP037 EBCDIC → ASCII (IBM Code Page 037, US) ────────────────────────
-- Same 256-entry table as Bridge_server/tn3270/ebcdic.js CP037_TO_ASCII.
-- Lua tables are 1-indexed here, so byte value b maps to CP037_TO_ASCII[b+1].
local CP037_TO_ASCII = {
  0x00,0x01,0x02,0x03,0x9C,0x09,0x86,0x7F,0x97,0x8D,0x8E,0x0B,0x0C,0x0D,0x0E,0x0F,
  0x10,0x11,0x12,0x13,0x9D,0x0A,0x08,0x87,0x18,0x19,0x92,0x8F,0x1C,0x1D,0x1E,0x1F,
  0x80,0x81,0x82,0x83,0x84,0x85,0x17,0x1B,0x88,0x89,0x8A,0x8B,0x8C,0x05,0x06,0x07,
  0x90,0x91,0x16,0x93,0x94,0x95,0x96,0x04,0x98,0x99,0x9A,0x9B,0x14,0x15,0x9E,0x1A,
  0x20,0xA0,0xE2,0xE4,0xE0,0xE1,0xE3,0xE5,0xE7,0xF1,0xA2,0x2E,0x3C,0x28,0x2B,0x7C,
  0x26,0xE9,0xEA,0xEB,0xE8,0xED,0xEE,0xEF,0xEC,0xDF,0x21,0x24,0x2A,0x29,0x3B,0x5E,
  0x2D,0x2F,0xC2,0xC4,0xC0,0xC1,0xC3,0xC5,0xC7,0xD1,0xA6,0x2C,0x25,0x5F,0x3E,0x3F,
  0xF8,0xC9,0xCA,0xCB,0xC8,0xCD,0xCE,0xCF,0xCC,0x60,0x3A,0x23,0x40,0x27,0x3D,0x22,
  0xD8,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0xAB,0xBB,0xF0,0xFD,0xFE,0xB1,
  0xB0,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,0xAA,0xBA,0xE6,0xB8,0xC6,0xA4,
  0xB5,0x7E,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0xA1,0xBF,0xD0,0x5B,0xDE,0xAE,
  0xAC,0xA3,0xA5,0xB7,0xA9,0xA7,0xB6,0xBC,0xBD,0xBE,0xDD,0xA8,0xAF,0x5D,0xB4,0xD7,
  0x7B,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0xAD,0xF4,0xF6,0xF2,0xF3,0xF5,
  0x7D,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0xB9,0xFB,0xFC,0xF9,0xFA,0xFF,
  0x5C,0xF7,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0xB2,0xD4,0xD6,0xD2,0xD3,0xD5,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0xB3,0xDB,0xDC,0xD9,0xDA,0x9F,
}

local function ebcdic_byte_to_ascii(b)
  return CP037_TO_ASCII[b + 1] or 0x3F -- '?' fallback
end

--- Strip 3270 orders from a data-record body and return the remaining bytes
-- translated to ASCII text, for banner pattern matching. Not a screen model.
function tn3270.extract_text(body)
  local out = {}
  local i = 1
  local n = #body
  while i <= n do
    local b = string.byte(body, i)
    if b == ORDER_SF then
      i = i + 2
    elseif b == ORDER_SFE then
      local count = string.byte(body, i + 1) or 0
      i = i + 2 + (2 * count)
    elseif b == ORDER_SBA then
      i = i + 3
    elseif b == ORDER_SA then
      i = i + 3
    elseif b == ORDER_MF then
      local count = string.byte(body, i + 1) or 0
      i = i + 2 + (2 * count)
    elseif b == ORDER_IC then
      i = i + 1
    elseif b == ORDER_PT then
      i = i + 1
    elseif b == ORDER_RA then
      i = i + 4
    elseif b == ORDER_EUA then
      i = i + 3
    else
      local a = ebcdic_byte_to_ascii(b)
      if a >= 0x20 and a <= 0x7E then
        out[#out + 1] = string.char(a)
      else
        out[#out + 1] = " "
      end
      i = i + 1
    end
  end
  return table.concat(out)
end

local function build_device_type_request(model, lu_name)
  local parts = { string.char(IAC, SB, OPT_TN3270E, TN3E_DEVICE_TYPE, TN3E_REQUEST) }
  parts[#parts + 1] = "IBM-" .. model
  if lu_name then
    parts[#parts + 1] = string.char(TN3E_CONNECT) .. lu_name
  end
  parts[#parts + 1] = string.char(IAC, SE)
  return table.concat(parts)
end

local function build_functions_request()
  return string.char(IAC, SB, OPT_TN3270E, TN3E_FUNCTIONS, TN3E_REQUEST,
    TN3E_FN_DATA_STREAM_CTL, IAC, SE)
end

-- ── Host-type / application fingerprinting ──────────────────────────────
-- Reimplemented in Lua patterns (not ported 1:1) from web3270's
-- Bridge_server/public/js/rendering.js _FP_RULES. Lua patterns have no
-- alternation or {m,n} repetition, so each JS regex becomes a short list of
-- literal alternatives instead of one combined pattern. Matched against the
-- upper-cased screen text, so all patterns below are written upper-case.
tn3270.HOST_RULES = {
  { name = "ISPF",      patterns = { "OPTION%s*===>", "ISREDIT", "ISPF%s+PRIMARY", "ISPF%s+OPTION", "PDF%s+MENU" } },
  { name = "SDSF",       patterns = { "SDSF%s+OUTPUT", "SDSF%s+STATUS", "SDSF%s+LOG", "SDSF%s+DA", "SDSF%s+JES", "FILTER%s+OWNER" } },
  { name = "CICS",       patterns = { "CICS%s", "DFHCS", "CESF%s+LOGOFF", "TRANSACTION%s" } },
  { name = "IMS",        patterns = { "IMS/VS", "MFS%s", "LTERM%s" } },
  -- NOTE: "ACF" is a substring of "RACF", so the "ACF ... LOGON" and bare
  -- "ACF2" patterns below use %f[%a]/%f[%A] frontier patterns (Lua's
  -- equivalent of regex \b, which Lua patterns don't have natively) --
  -- without them, a plain RACF LOGON screen substring-matches as ACF2.
  -- Caught via a live test against web3270's mock LPAR (a real RACF logon
  -- screen was misclassified ACF2 before this fix); the original JS
  -- rendering.js _FP_RULES has this same gap unfixed, esm-fingerprint.js's
  -- RULES table has \b there and is what this was checked against.
  { name = "ACF2",       patterns = { "%f[%a]ACF2%f[%A]", "LOGONID%s*:", "LOGONID%s*===>", "%f[%a]ACF%s+LOGON%f[%A]", "%f[%a]NULLID%f[%A]" } },
  { name = "TopSecret",  patterns = { "CA[%- ]TOP SECRET", "TOP SECRET/MVS", "TSSUTIL", "TSS%s+LOGON", "ACCESSOR" } },
  { name = "RACF",       patterns = { "%f[%a]RACF%f[%A]", "ICH%d%d%d[IEWA]", "ICH%d%d%d%d[IEWA]", "ICH%d%d%d%d%d[IEWA]", "NEW%s+PASSWORD", "REVOKED" } },
  { name = "TSO",        patterns = { "READY%s*$", "TSO/E%s", "LOGON%s+IN%s+PROGRESS" } },
  { name = "z/VM",       patterns = { "Z/VM%s", "CMS", "CP%s+QUERY", "RECONNECT" } },
  { name = "LOGON",      patterns = { "ENTER%s+USERID", "ENTER%s+PASSWORD", "IBM%s+Z/OS" } },
}

--- Classify which host application/panel type a screen is showing.
-- Returns the first matching rule name (rule order = priority, same as
-- the JS original), or "unknown".
function tn3270.classify_host(text)
  local upper = text:upper()
  for _, rule in ipairs(tn3270.HOST_RULES) do
    for _, pat in ipairs(rule.patterns) do
      if upper:find(pat) then
        return rule.name
      end
    end
  end
  return "unknown"
end

-- ── External security manager (ESM) fingerprinting ──────────────────────
-- Reimplemented in Lua patterns from web3270's
-- Bridge_server/features/esm-fingerprint.js RULES. Same weighted-scoring
-- shape, simplified to a single-screen read (that module accumulates
-- evidence across a whole live session; an NSE script only ever gets one
-- screen, so there's no cross-screen state to track here).
tn3270.ESM_RULES = {
  -- IBM RACF
  { id = "racf-ich-msgid", product = "RACF", kind = "msgid", weight = 10,
    patterns = { "ICH%d%d%d[IEWA]", "ICH%d%d%d%d[IEWA]", "ICH%d%d%d%d%d[IEWA]" } },
  { id = "racf-irr-msgid", product = "RACF", kind = "msgid", weight = 10,
    patterns = { "IRR%d%d%d[IEWA]", "IRR%d%d%d%d[IEWA]", "IRR%d%d%d%d%d[IEWA]" } },
  { id = "racf-ikj564", product = "RACF", kind = "msgid", weight = 6,
    patterns = { "IKJ564%d%d[IEWA]" } },
  { id = "racf-logon-hdr", product = "RACF", kind = "banner", weight = 6,
    patterns = { "RACF%s+LOGON" } },
  { id = "racf-word", product = "RACF", kind = "banner", weight = 4,
    patterns = { "%f[%a]RACF%f[%A]" } }, -- \bRACF\b in the JS original
  { id = "racf-revoked", product = "RACF", kind = "behavior", weight = 3,
    patterns = { "HAS BEEN REVOKED" } },

  -- Broadcom ACF2. "ACF" is a substring of "RACF", so these use
  -- %f[%a]/%f[%A] frontier patterns (Lua's \b) same as the JS originals'
  -- \b -- without them a RACF screen scores false ACF2 evidence. Caught via
  -- a live test against web3270's mock LPAR.
  { id = "acf2-msgid", product = "ACF2", kind = "msgid", weight = 10,
    patterns = { "%f[%a]ACF0%d%d%d%d%f[%A]" } },
  { id = "acf2-word", product = "ACF2", kind = "banner", weight = 7,
    patterns = { "%f[%a]ACF2%f[%A]" } },
  { id = "acf2-logonid", product = "ACF2", kind = "banner", weight = 6,
    patterns = { "LOGONID%s*:", "LOGONID%s*===>" } },
  { id = "acf2-logon-hdr", product = "ACF2", kind = "banner", weight = 6,
    patterns = { "%f[%a]ACF%s+LOGON%f[%A]" } },
  { id = "acf2-noncancel", product = "ACF2", kind = "behavior", weight = 2,
    patterns = { "NON%-CANCEL", "NONCANCEL" } },

  -- Broadcom Top Secret
  { id = "tss-msgid", product = "TopSecret", kind = "msgid", weight = 10,
    patterns = { "TSS%d%d%d%d[EIWA]" } },
  { id = "tss-ca-name", product = "TopSecret", kind = "banner", weight = 8,
    patterns = { "CA[%- ]TOP SECRET", "TOP SECRET/MVS" } },
  { id = "tss-logon-hdr", product = "TopSecret", kind = "banner", weight = 6,
    patterns = { "TSS%s+LOGON", "TOP SECRET LOGON" } },
  { id = "tss-tssutil", product = "TopSecret", kind = "banner", weight = 5,
    patterns = { "TSSUTIL" } },
  { id = "tss-accessorid", product = "TopSecret", kind = "banner", weight = 4,
    patterns = { "ACCESSOR%s*ID" } },
}

local ESM_K = 4 -- confidence denominator softener, same constant as the JS original

--- Classify which external security manager (if any) a screen names.
-- Single-screen version of EsmFingerprint.observe()+verdict() from
-- esm-fingerprint.js -- an NSE script only ever gets one screen to look at,
-- so there's no session-long evidence trail to accumulate.
-- @return table { product, confidence, runnerUp, scores, evidence }
function tn3270.classify_esm(text)
  local upper = text:upper()
  local scores = { RACF = 0, ACF2 = 0, TopSecret = 0 }
  local has_msgid = { RACF = false, ACF2 = false, TopSecret = false }
  local evidence = {}

  for _, rule in ipairs(tn3270.ESM_RULES) do
    for _, pat in ipairs(rule.patterns) do
      local m = upper:find(pat)
      if m then
        scores[rule.product] = scores[rule.product] + rule.weight
        if rule.kind == "msgid" then has_msgid[rule.product] = true end
        evidence[#evidence + 1] = { ruleId = rule.id, product = rule.product,
          kind = rule.kind, weight = rule.weight, matched = upper:sub(m, m + 20) }
        break -- one hit per rule per screen, same as the JS de-dup-by-rule
      end
    end
  end

  local products = { "RACF", "ACF2", "TopSecret" }
  table.sort(products, function(a, b) return scores[a] > scores[b] end)
  local top, second = products[1], products[2]

  if scores[top] == 0 then
    return { product = "unknown", confidence = 0, runnerUp = nil, scores = scores, evidence = {} }
  end

  local confidence = scores[top] / (scores[top] + scores[second] + ESM_K)
  if has_msgid[top] then
    confidence = math.max(confidence, 0.85)
  end

  return {
    product = top,
    confidence = confidence,
    runnerUp = (scores[second] > 0) and second or nil,
    scores = scores,
    evidence = evidence,
  }
end

-- ── Negotiation ──────────────────────────────────────────────────────────

--- Send our DEVICE-TYPE REQUEST, at most once per session.
--
-- RFC 2355 lets either side initiate this: a host can prompt with
-- "SEND DEVICE-TYPE" first, or the client can just send its REQUEST
-- unprompted right after WILL/DO TN3270E is agreed (this is what
-- session.js's own client does, unconditionally -- see _sendTn3270eDeviceType
-- in Bridge_server/tn3270/session.js). Some hosts only implement the second
-- style and never send a SEND prompt at all -- confirmed against web3270's
-- own z/VM mock, which waits passively for the client to go first and would
-- hang forever otherwise. So this gets called from both places: right after
-- WILL TN3270E (proactively, covering that kind of host) and again if a
-- SEND DEVICE-TYPE prompt arrives anyway (covering the mock-lpar.js kind
-- of host) -- the `sent` guard makes the second call a no-op either way.
local function send_device_type_request_once(sock, model, lu_name, sent, log)
  if sent.device_type_request then return end
  sent.device_type_request = true
  sock:send(build_device_type_request(model, lu_name))
  log("sent", "DEVICE-TYPE REQUEST IBM-" .. model ..
    (lu_name and (" CONNECT " .. lu_name) or ""))
end

--- Handle one TN3270E subnegotiation payload (the bytes between "IAC SB"
-- and "IAC SE", i.e. opt=sub[1], func=sub[2], subfunc=sub[3], payload from
-- sub[4] on -- matching the indexing convention of session.js's
-- _decodeTn3270eSubneg, just 1-based instead of 0-based).
local function handle_subneg(sub, result, model, lu_name, sock, log, sent)
  local opt = string.byte(sub, 1)

  -- Classic TN3270 (and plenty of TN3270E hosts that probe TERMINAL-TYPE
  -- first) follow DO TERMINAL-TYPE with SB TERMINAL-TYPE SEND and sit silent
  -- until the client answers with its terminal name. Ignoring this made the
  -- scan time out against such hosts (c3270 connected fine, this didn't).
  -- Capped at a few replies in case a host cycles through its type list.
  if opt == OPT_TTYPE then
    if string.byte(sub, 2) == TTYPE_SEND and sent.ttype_is < 3 then
      sent.ttype_is = sent.ttype_is + 1
      local name = "IBM-" .. model
      sock:send(string.char(IAC, SB, OPT_TTYPE, TTYPE_IS) .. name .. string.char(IAC, SE))
      log("sent", "TERMINAL-TYPE IS " .. name)
    end
    return
  end

  if opt ~= OPT_TN3270E then return end
  local func = string.byte(sub, 2)
  local subfunc = string.byte(sub, 3)

  if func == TN3E_SEND and subfunc == TN3E_DEVICE_TYPE then
    -- RFC 2355: SEND is its own top-level TN3270E function carrying
    -- DEVICE-TYPE as its argument, i.e. byte order [[opt, SEND, DEVICE-TYPE]]
    -- -- SEND leads here, unlike the DEVICE-TYPE-leads order used by the
    -- REQUEST/IS/REJECT branches below. Confirmed against a live mock LPAR;
    -- see docs/NEGOTIATION-NOTES.md.
    log("recv", "SEND DEVICE-TYPE")
    send_device_type_request_once(sock, model, lu_name, sent, log)

  elseif func == TN3E_DEVICE_TYPE and subfunc == TN3E_IS then
    local payload = string.sub(sub, 4)
    local lu_idx = string.find(payload, string.char(TN3E_CONNECT), 1, true)
    if lu_idx then
      result.deviceType = string.sub(payload, 1, lu_idx - 1)
      result.luGranted = string.sub(payload, lu_idx + 1)
    else
      result.deviceType = payload
    end
    result.tn3270e = true
    log("recv", "DEVICE-TYPE IS " .. (result.deviceType or "?") ..
      (result.luGranted and (" LU=" .. result.luGranted) or ""))
    if not sent.functions_request then
      sent.functions_request = true
      sock:send(build_functions_request())
      log("sent", "FUNCTIONS REQUEST [DATA-STREAM-CTL]")
    end

  elseif func == TN3E_DEVICE_TYPE and subfunc == TN3E_REJECT then
    local reason = string.byte(sub, 4)
    result.rejected = true
    result.rejectReason = TN3E_REASON_NAMES[reason] or tostring(reason)
    log("recv", "DEVICE-TYPE REJECT reason=" .. result.rejectReason)

  elseif func == TN3E_FUNCTIONS then
    local fns = {}
    for k = 4, #sub do fns[#fns + 1] = string.byte(sub, k) end
    result.functionsGranted = fns
    log("recv", (subfunc == TN3E_IS) and "FUNCTIONS IS" or "FUNCTIONS REQUEST")
  end
end

--- Negotiate TN3270E on an already-connected nmap socket, then read the
-- first inbound 3270 data record.
--
-- @param sock a connected nmap socket (plain or TLS -- caller decides which)
-- @param opts { model = "3278-2", lu_name = nil, timeout = 8000 }
-- @return status (bool), result (table) or error string
function tn3270.negotiate(sock, opts)
  opts = opts or {}
  local model = opts.model or "3278-2"
  local timeout = opts.timeout or 8000
  sock:set_timeout(timeout)

  local result = {
    tn3270e = false,
    deviceType = nil,
    luRequested = opts.lu_name,
    luGranted = nil,
    rejected = false,
    rejectReason = nil,
    functionsGranted = {},
    screenText = nil,
    log = {},
  }

  local function log(dir, note)
    result.log[#result.log + 1] = dir .. ": " .. note
    stdnse.debug2("tn3270: %s: %s", dir, note)
  end

  local buf = ""    -- unconsumed bytes read from the socket
  local record = {} -- accumulated data bytes for the current 3270 record
  local got_screen = false

  -- Idempotency guards. Some hosts (the web3270 mock LPARs among them)
  -- reply to the client's own WILL/DO ack with a fresh, unconditional
  -- re-offer of the same option, with no negotiation-state tracking on
  -- their side -- see docs/NEGOTIATION-NOTES.md "mutual re-ack loop". Real
  -- clients (session.js's own `_willSend`/`_doSent` flags among them) only
  -- ever answer a given option once; without the same guard here, that
  -- kind of host and this script would just keep re-acking each other
  -- forever.
  local sent = {
    will_tn3270e = false, will_ttype = false, will_eor = false, will_binary = false,
    do_binary = false, do_eor = false, do_tn3270e = false,
    device_type_request = false, functions_request = false,
    ttype_is = 0,
  }

  local function fetch()
    local status, data = sock:receive_bytes(1)
    if not status then return false end
    log("recv", "raw " .. #data .. " bytes: " .. stdnse.tohex(string.sub(data, 1, 48)) ..
      (#data > 48 and "..." or ""))
    buf = buf .. data
    return true
  end

  while not got_screen do
    local i = 1
    while i <= #buf do
      local b = string.byte(buf, i)

      if b ~= IAC then
        record[#record + 1] = string.char(b)
        i = i + 1
      else
        if i + 1 > #buf then break end -- need the command byte, wait for more
        local cmd = string.byte(buf, i + 1)

        if cmd == IAC then
          record[#record + 1] = string.char(IAC) -- escaped 0xFF data byte
          i = i + 2

        elseif cmd == DO_ or cmd == DONT or cmd == WILL or cmd == WONT then
          if i + 2 > #buf then break end -- need the option byte
          local opt = string.byte(buf, i + 2)
          if opt == OPT_TN3270E and cmd == DO_ then
            log("recv", "IAC DO TN3270E")
            if not sent.will_tn3270e then
              sent.will_tn3270e = true
              sock:send(string.char(IAC, WILL, OPT_TN3270E))
              log("sent", "IAC WILL TN3270E")
            end
            -- Don't wait to be asked -- some hosts (web3270's z/VM mock
            -- among them) never send a SEND DEVICE-TYPE prompt at all and
            -- just expect the client to go first. Guarded, so this is a
            -- no-op if a SEND prompt shows up later anyway.
            send_device_type_request_once(sock, model, opts.lu_name, sent, log)
          elseif opt == OPT_TN3270E and cmd == WILL then
            -- Host offering TN3270E on its own side too -- accept, once.
            if not sent.do_tn3270e then
              sent.do_tn3270e = true
              sock:send(string.char(IAC, DO_, OPT_TN3270E))
            end
          elseif opt == OPT_TTYPE and cmd == DO_ then
            if not sent.will_ttype then
              sent.will_ttype = true
              sock:send(string.char(IAC, WILL, OPT_TTYPE))
            end
          elseif opt == OPT_EOR and cmd == DO_ then
            if not sent.will_eor then
              sent.will_eor = true
              sock:send(string.char(IAC, WILL, OPT_EOR))
            end
          elseif opt == OPT_BINARY and cmd == DO_ then
            if not sent.will_binary then
              sent.will_binary = true
              sock:send(string.char(IAC, WILL, OPT_BINARY))
            end
          elseif opt == OPT_BINARY and cmd == WILL then
            -- Host offering binary on its own side -- accept, once.
            if not sent.do_binary then
              sent.do_binary = true
              sock:send(string.char(IAC, DO_, OPT_BINARY))
            end
          elseif opt == OPT_EOR and cmd == WILL then
            -- Host offering EOR on its own side -- accept, once.
            if not sent.do_eor then
              sent.do_eor = true
              sock:send(string.char(IAC, DO_, OPT_EOR))
            end
          elseif cmd == DO_ then
            sock:send(string.char(IAC, WONT, opt)) -- unsupported option requested of us
          elseif cmd == WILL then
            sock:send(string.char(IAC, DONT, opt)) -- unsupported option offered by host
          end
          i = i + 3

        elseif cmd == SB then
          local j = i + 2
          local se_at = nil
          while j <= #buf - 1 do
            if string.byte(buf, j) == IAC and string.byte(buf, j + 1) == SE then
              se_at = j
              break
            end
            j = j + 1
          end
          if not se_at then break end -- incomplete subnegotiation, wait for more
          local sub = string.sub(buf, i + 2, se_at - 1)
          handle_subneg(sub, result, model, opts.lu_name, sock, log, sent)
          i = se_at + 2

        elseif cmd == EOR then
          got_screen = true
          i = i + 2
          break

        else
          i = i + 2 -- other 2-byte telnet commands (e.g. NOP): skip
        end
      end
    end

    buf = string.sub(buf, i)
    if got_screen then break end
    if not fetch() then
      if #record == 0 then
        return false, "no 3270 screen received during TN3270E negotiation (see trace)", result
      end
      break
    end
  end

  local body = table.concat(record)
  -- Once TN3270E is negotiated, every data record carries a 5-byte header
  -- (DATA-TYPE, REQUEST-FLAG, RESPONSE-FLAG, SEQ-NUMBER x2) before the 3270
  -- orders/data -- see docs/NEGOTIATION-NOTES.md. Classic TN3270 (no
  -- TN3270E, e.g. after a DEVICE-TYPE REJECT) has no such header.
  if result.tn3270e and #body >= 5 then
    body = string.sub(body, 6)
  end
  if #body > 0 then
    result.screenText = tn3270.extract_text(body)
  end

  return true, result
end

-- ── Shared NSE action body ───────────────────────────────────────────────

--- Connect, negotiate, and classify -- the whole scan in one call, shared
-- by scripts/tn3270-info.nse (the real script, portrule 23/992) and
-- test/tn3270-info-local.nse (the same thing with the mock LPARs' default
-- ports added to the portrule, for local testing without root). Keeping
-- this in the library instead of duplicated in each .nse file means the
-- two scripts can never drift apart from each other.
--
-- @param host, port  the values Nmap's portrule/action machinery passes in
-- @return a stdnse output table, or a formatted error string
function tn3270.scan(host, port)
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

  local ok, result, partial = tn3270.negotiate(sock, { model = "3278-2" })
  sock:close()

  if not ok then
    -- Returned as a normal output table, not format_output(false, ...):
    -- NSE hides failed-status output unless -d is on, which made failures
    -- look like the script never ran. Include the negotiation trace so a
    -- failure is diagnosable from one plain run.
    local out = stdnse.output_table()
    out.error = tostring(result)
    if partial and #partial.log > 0 then out.trace = partial.log end
    return out
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

return tn3270
