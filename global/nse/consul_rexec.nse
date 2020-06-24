local http = require "http"
local nmap = require "nmap"
local json = require "json"
local stdnse = require "stdnse"

name = 'Consul service rexec detection'
description = [[This script checks if a Consul agent is vulnerable to a remote code execution due to a user
  remotely registering a service (even being non authenticated) with a script checks. In that
  case, Consul will start the health check even before the service is either registered and
  propagated or even rejected.]]
nse_id = 'metascanfeed-consul_rexec'
score = 10

author = "c.michaud"
license = "Apache version 2.0 http://www.apache.org/licenses/LICENSE-2.0"
categories = {"discovery", "safe", "consul", "rexec", "services"}

---
-- Script is executed for any port where Consul is detected.
---
portrule = function(host, port)
  return port.version.product == 'HashiCorp Consul agent'
end


---
-- Helper function to perform a transformation of a list.
---
function map(func, array)
  local new_array = {}
  for i,v in ipairs(array) do
    new_array[i] = func(v)
  end
  return new_array
end


---
-- Check if table contains a certain value.
---
local function has_value (tab, val)
  for index, value in ipairs(tab) do
    if value == val then
      return true
    end
  end

  return false
end


---
-- Check if the script checks are enabled in configuration.
---
script_checks_enabled = function(agent_info)
  return agent_info["Config"]["EnableScriptChecks"] or agent_info["DebugConfig"]["EnableScriptChecks"] or agent_info["DebugConfig"]["EnableRemoteScriptChecks"]
end


---
-- Check if the remote write is allowed and not restricted to localhost
---
is_remote_write_allowed = function(agent_info)
  local allow_from = agent_info['DebugConfig']['AllowWriteHTTPFrom']
  if allow_from == nil then
    return true
  end

  local ips = map(function(e) return e['IP'] end, allow_from)
  if #allow_from == 2 and has_value(ips, '127.0.0.0') and has_value(ips, '::1') then
    return false
  end
  return true
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
-- Check the agent configuration to see if it is vulnerable.
---
action = function(host, port)
  local response = http.get(host, port.number, '/v1/agent/self')
  if response.status ~= 200 then
    return detected(false, "Error status...")
  end

  local ok, agent_info = json.parse(response.body)
  if not ok then
    return detected(false, "No JSON. Probably not Consul.")
  end

  if script_checks_enabled(agent_info) and is_remote_write_allowed(agent_info) then
    return detected(true)
  end
  return detected(false)
end

