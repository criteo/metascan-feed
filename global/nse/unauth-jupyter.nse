local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"


name = 'Unauthenticated Jupyter'
description = [[
This script checks if the service is an unauthenticated Jupyter
]]
nse_id = 'metascanfeed-unauthenticated-jupyter'
score = 10

author = 'c.michaud'
license = "Apache version 2.0 http://www.apache.org/licenses/LICENSE-2.0"
categories = { "discovery", "safe", "rce" }

---
-- Script is executed for any http service detected.
---
portrule = shortport.http

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
-- Check if it is vulnerable.
---
function action (host, port)
  local response = http.get(host, port.number, "/")
  stdnse.debug(1, "Endpoint status '%s'", response.status)

  if response.status == 200 then
    i0, j0 = string.find(response.body, 'Jupyter Notebook')
    -- Find the New button on main page (this is the button to create a notebook).
    i1, j1 = string.find(response.body, 'New')

    if i0 and j0 and i1 and j1 then
      return detected(true, "Unauthenticated Jupyter discovered.")
    end
  end

  return detected(false, "Not an unauthenticated Jupyter.")
end
