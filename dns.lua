local resolver = require("lib.resolver")
local server = require("lib.server")
local socket = require("socket")
local http = require("socket.http")
local config = require("config")


function table_concat(t1,t2)
    for i=1,#t2 do
        t1[#t1+1] = t2[i]
    end
    return t1
end


local udp = socket.udp()

local r, err = resolver:new{
  nameservers = { config.upstream_dns1,  config.upstream_dns2 },
  retrans = 5,  -- 5 retransmissions on receive timeout
  timeout = 2000,  -- 2 sec
}


local res, err = udp:setsockname(config.listen_on, 53)
if not res then
  print(err)
  os.exit(1)
end


while 1 do

  local dns = server:new()

  local req, ip, port = udp:receivefrom()

  local request, err = dns:decode_request(req)

  if not request then
    print("failed to decode request: ", err)
    local resp = dns:encode_response()
    local ok, err = udp:send(resp)
    if not ok then
      print("failed to send: ", err)
    end
  end

  local query = request.questions[1]
  print("qname: ", query.qname, " qtype: ", query.qtype)

  if query.qtype == server.TYPE_CNAME then

    local answers, err, tries = r:query(query.qname, {qtype = query.qtype }, {})

    for i, ans in ipairs(answers) do
      dns:create_cname_answer(query.qname, ans.ttl, ans.cname)
    end

  elseif query.qtype == server.TYPE_A then
    local answers = {}
    for i = 1,3,1 do
      local inanswers, err, tries = r:query(query.qname, {qtype = query.qtype }, {})
      if answers then
        table_concat(answers, inanswers)
      end
    end
    local cnt = 0

    local banned = {}
    local available = {}
    for i, ans in ipairs(answers) do
      if ans.type == server.TYPE_A then
        local b, c, h = http.request("http://api.antizapret.info/get.php?item=".. ans.address .."&type=small")
        if b == "1" then
--          print("Address "..ans.address.." banned. Skipping")
          banned[#banned+1]=ans.address
        else
--          print("Address "..ans.address.." available")
          available[#available+1]=ans.address
          dns:create_a_answer(ans.name, ans.ttl, ans.address)
          cnt = cnt + 1
        end

      elseif ans.type == server.TYPE_CNAME then
        dns:create_cname_answer(ans.name, ans.ttl, ans.cname)
      end
    end
    if cnt < 1 then
      print("No not-banned addresses available =/")
    end
    print("Available: "..table.concat(available, ", "))
    print("Banned: "..table.concat(banned, ", "))

  elseif query.qtype == server.TYPE_AAAA then
    local answers, err, tries = r:query(query.qname, {qtype = query.qtype }, {})

    for i, ans in ipairs(answers) do

      if ans.type == server.TYPE_AAAA then
        dns:create_aaaa_answer(ans.name, ans.ttl, ans.address)
      elseif ans.type == server.TYPE_CNAME then
        dns:create_cname_answer(ans.name, ans.ttl, ans.cname)
      end

    end

  end

  local resp = dns:encode_response()
  local ok, err = udp:sendto(resp, ip, port)
  if not ok then
    print("failed to send: ", err)
    os.exit(1)
  end

end
