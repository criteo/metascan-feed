local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

name = 'HTTP server verbose banners'
description = [['HTTP web server returns in HTTP response some response headers helping
attacker to fingerprint software stack used by applications and should not.]]
nse_id = 'metascanfeed-http-server-fingerprint'
score = 6

author = "d.tilloy"
license = "Apache version 2.0 http://www.apache.org/licenses/LICENSE-2.0"
categories = {"discovery", "safe", "web"}

---
-- Script is executed for any open port
---
portrule = function(host, port)
  if (port.protocol ~= "tcp" or port.state ~= "open") then
    return false
  end
  if (port.service == nil or port.service == "" or port.service == "unknown") then
    return true -- nmap not running with service detection
  end
  if (port.service == "http" or port.service == "https") then
      return true
  end
  return false
end

---
-- Produce a formatted output for metascan to parse.
-- The caller can tell that the vulnerability has been detected and
-- give additional information that will be present in the output.
---
detected = function(detected, details, additional_info)
  local output = stdnse.output_table()
  output.nse_id = nse_id
  output.name = name
  output.description = string.gsub(description, '\n', ' ')
  output.score = score
  output.detected = detected
  output.details = details
  output.additional_info = additional_info
  return output
end

---
-- Check for verbose response banners
---
action = function(host, port)
  local options = {}
  options["timeout"] = 5000 -- in milliseconds

  local response = http.get(host, port.number, '/', options)
  if response.header['x-aspnet-version'] ~= nil then
    return detected(true, {{key="detected_header", value="x-aspnet-version"}})
  end
  -- note using IP and not hostname, header "x-powered-by"
  -- is not returned (at least for marketing.criteo.com)
  if response.header['x-powered-by'] ~= nil then
    return detected(true, {{key="detected_header", value="X-Powered-By"}})
  end

  if response.header['server'] ~= nil then
    return detected(true, {{key="detected_header", value="server"}})
  end

  return detected(false, nil, "No header helping to fingerprint software stack.")
end
