# lua-proxy-dns
dns-proxy with automatic banned ip detection

# Requirements
luajit  
luasocket

# Running
Get blacklist dump in json format: `wget 'https://reestr.rublacklist.net/api/v2/ips/json' -O blacklist.json`
Modify config.lua, run with `luajit ./dns.lua`  
You may need to run it as root, to bind to port 53
