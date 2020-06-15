local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local json = require "json"

name = 'PHP Composer configuration file detection'
description = [[This script detects 'composer.json' or 'composer.lock' files. These files are
  dangerous as they list and exposed all modules with their version used by the application.
  An attacker can easilly detect a vulnerable third party module used and exploit it to gain
  privileges or extract data unexpectidely from the Web server.]]
nse_id = 'metascanfeed-php-composer'
score = 8

author = "d.tilloy"
license = "Apache version 2.0 http://www.apache.org/licenses/LICENSE-2.0"
categories = {"discovery", "safe", "php", "composer", "environment"}

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
  output.description = string.gsub(description, '\n', '')
  output.score = score
  output.detected = detected
  output.details = details
  output.additional_info = additional_info
  return output
end

---
-- Check if composer.lock or composer.json files can be retrieved
---
action = function(host, port)
  local options = {}
  options["timeout"] = 5000 -- in milliseconds

  -- Detection is positive when response is 200 *and* payload is valid JSON
  -- for composer.lock *or* composer.json

  local response = http.get(host, port.number, '/composer.lock', options)
  local ok, data = json.parse(response.body)
  if response.status == 200 and ok then
    return detected(true, {{key="target_path", value="/composer.lock"}})
  end

  response = http.get(host, port.number, '/composer.json', options)
  ok, data = json.parse(response.body)
  if response.status == 200 and ok then
    return detected(true, {{key="target_path", value="/composer.json"}})
  end

  return detected(false, nil, "No available /composer.json or /composer.lock files.")
end
