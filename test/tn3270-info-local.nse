-- Test-only copy of scripts/tn3270-info.nse with web3270's mock LPAR
-- default ports (3270 = mock-lpar.js z/OS, 3271 = mock-zvm.js z/VM) added to
-- the portrule, so it can be run without root against `node mock-lpar.js`'s
-- default, non-privileged port instead of needing MOCK_PORT=23 + sudo.
--
-- Not a real scanning script -- never point this at an actual network, only
-- at localhost mocks. The real script is scripts/tn3270-info.nse; this file
-- shares all its logic via lib/tn3270.lua's tn3270.scan(), so the two can
-- never drift apart -- only the portrule differs.
--
-- @usage
-- nmap --script test/tn3270-info-local.nse -p 3270,3271 localhost

local shortport = require "shortport"
local tn3270 = require "tn3270"

description = "Local-mock-only test variant of tn3270-info -- see test/README.md."

author = "Britley Hoff"
license = "Same as the parent repo (GPLv3) - see LICENSE"
categories = { "discovery", "safe" }

portrule = shortport.port_or_service({ 23, 992, 3270, 3271 }, { "tn3270", "tn3270s" }, "tcp")

action = function(host, port)
  return tn3270.scan(host, port)
end
