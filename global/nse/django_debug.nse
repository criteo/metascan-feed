local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

name = 'Django debug detection'
description = [[This script if django is ran in debug mode. Running in debug mode is dangerous
  in production because it allows to see all environment variables.
  This caused issues reported by bug bounty (publicly visible credentials) on django and on other
  frameworks.]]
nse_id = 'metascanfeed-django-debug'
score = 10

author = "g.seux"
license = "Apache version 2.0 http://www.apache.org/licenses/LICENSE-2.0"
categories = {"discovery", "safe", "python", "django", "environment", "debug"}

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
      -- identify django
      return port.version.product == "WSGIServer"
  end
  return false
end

---
-- Produce a formatted output for metascan to parse.
-- The caller can tell that the vulnerability has been detected and
-- give additional information that will be present in the output.
---
detected = function(detected, additional_info)
  local output = stdnse.output_table()
  output.nse_id = nse_id
  output.name = name
  output.description = string.gsub(description, '\n', '')
  output.score = score
  output.detected = detected
  output.additional_info = additional_info
  return output
end

---
-- Check the server response to detect django with DEBUG set to True configuration.
---
action = function(host, port)
  local options = {}
  options["timeout"] = 5000 -- in milliseconds
  local response = http.get(host, port.number, '/security-scan-nse-criteofeed-django-debug', options)
  if response.status ~= 404 then
    return detected(false, "Wrong http code")
  end

  local body = response.body

  local found = string.find(body, "You're seeing this error because you have <code>DEBUG = True</code>")
  if not found then
      return detected(false, "404 page does not contain django DEBUG warning")
  end
  return detected(true)
end
