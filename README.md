# lua-proxy-dns
dns-proxy with automatic banned ip detection

# Requirements
- luajit
- luasocket
- lua-cjson

# Running
1. Get blacklist dump in json format: `wget 'https://reestr.rublacklist.net/api/v2/ips/json' -O blacklist.json`
2. Modify config.lua
3. run `luajit ./dns.lua`
4. .....
5. PROFIT!

You may need to run it as root, to bind to port 53
