local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Detects if the service is serving an nginx status page
]]

---
--@output
-- Nmap scan report for example.com (1.2.3.4)
-- PORT   STATE SERVICE
-- 80/tcp open  nginx
-- |_nginx-status: Found nginx status page

author = "John Leach"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.http

function action(host, port)
  local resp, redirect_url, title

  resp = http.get( host, port, '/nginx_status' )

  if ( not(resp.body) ) then
    return
  end

  if string.match(resp.body, "Active connections:") and string.match(resp.body, "server accepts handled requests") then
     port.version.name = 'nginx'
     nmap.set_port_version(host,port)
     return "Found nginx status page"
  end

end
