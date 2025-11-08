-- Flow ID tracking (batch once; LUA passes hex like "220a567b...")

local flow_proto  = Proto("flowid", "Flow ID Tracker")
local flow_field  = ProtoField.string("flowid.id", "Flow ID")
flow_proto.fields = { flow_field }

local f_udp  = Field.new("udp")
local f_tcp  = Field.new("tcp")
local f_data = Field.new("data.data")
local udp_tap = Listener.new("udp")

-- state
local ready = false
local items = {}            -- { {hex=..., us=udp_src_port, ud=udp_dst_port}, ... }
local udp_map, tcp_map = {}, {}

local function nport(p) return tonumber(tostring(p)) or 0 end

-- fast bytearray → hex (lowercase)
local function bytes_to_hex(ba)
  local n = ba:len()
  local out = {}
  for i = 0, n - 1 do
    out[#out + 1] = string.format("%02x", ba:get_index(i))
  end
  return table.concat(out)
end

-- run python ONCE: input has one HEX line per payload; output "flow_id \t tcp_port"
local function run_python_once(recs)
  local inpath, outpath = os.tmpname(), os.tmpname()

  -- write hex lines (same order as recs)
  local f = assert(io.open(inpath, "wb"))
  for i = 1, #recs do f:write(recs[i].hex, "\n") end
  f:close()

  print(inpath)
  -- adjust python path/flags to your env
  os.execute(
    [[python -S -u "C:\Users\danbi\flow-id-wireshark-plugin\wireshark\parse_metadata_batch.py" "]]..inpath..[[" "]]..outpath..[["]]
  )


  -- read results back in the SAME order; pair with stored UDP ports
  local r = assert(io.open(outpath, "rb"))
  local i = 1
  for line in r:lines() do
    local flow_id, tcp_port = line:match("^([%w%-]+)%s*\t%s*(%d*)%s*$")
    local it = recs[i]
    if flow_id and it then
      if it.us and it.us > 0 then udp_map[it.us] = flow_id end
      if it.ud and it.ud > 0 then udp_map[it.ud] = flow_id end
      if tcp_port and #tcp_port > 0 then tcp_map[tonumber(tcp_port)] = flow_id end
    end
    i = i + 1
  end
  r:close()

  ready = true
end

-- collect UDP payloads + ports during first pass
function udp_tap.packet(pinfo, tvb)
  if ready then return end
  local d = f_data()
  if not d then return end
  local r  = d.range
  local ba = r:bytes()
  items[#items + 1] = {
    hex = bytes_to_hex(ba),
    us  = nport(pinfo.src_port),
    ud  = nport(pinfo.dst_port),
  }
end

function udp_tap.draw()
  if not ready and #items > 0 then
    run_python_once(items)
    retap_packets()
  end
end

function flow_proto.init()
  ready = false
  items = {}
  udp_map, tcp_map = {}, {}
end

-- post-dissector: read only from caches (fast)
function flow_proto.dissector(tvb, pinfo, tree)
  if not ready then return end
  local flow_id
  if f_udp() then
    local sp, dp = nport(pinfo.src_port), nport(pinfo.dst_port)
    flow_id = udp_map[sp] or udp_map[dp]
  elseif f_tcp() then
    local sp, dp = nport(pinfo.src_port), nport(pinfo.dst_port)
    flow_id = tcp_map[sp] or tcp_map[dp]
  end
  if flow_id then
    tree:add(flow_proto, "Flow Association"):add(flow_field, flow_id)
    if pinfo.cols and pinfo.cols.info then
      pinfo.cols.info:append(" [flow_id:" .. flow_id .. "]")
    end
  end
end

register_postdissector(flow_proto)
