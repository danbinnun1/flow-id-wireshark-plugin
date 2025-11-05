local flow_proto = Proto("flowid", "Flow ID Tracker")
local flow_field = ProtoField.string("flowid.id", "Flow ID")
flow_proto.fields = { flow_field }

local udp_field = Field.new("udp")
local tcp_field = Field.new("tcp")
local data_field = Field.new("data.data")

local udp_sessions = {}
local tcp_sessions = {}
local tcp_port_map = {}
local pending = {}

local function session_key(proto, pinfo)
    local a1, a2 = tostring(pinfo.src), tostring(pinfo.dst)
    local p1 = tonumber(tostring(pinfo.src_port)) or 0
    local p2 = tonumber(tostring(pinfo.dst_port)) or 0
    if a1 > a2 or (a1 == a2 and p1 > p2) then
        a1, a2 = a2, a1
        p1, p2 = p2, p1
    end
    return string.format("%s:%s:%d-%s:%d", proto, a1, p1, a2, p2)
end

local function parse_payload(bytes)
    if not bytes or bytes:len() == 0 then
        return nil, nil
    end
    local payload = bytes:raw(0, bytes:len())
    local id = payload:match("flow_id=([%w%-]+)")
    if not id then
        return nil, nil
    end
    local port = payload:match("tcp_port=(%d+)")
    if port then
        port = tonumber(port)
    end
    return id, port
end

local function remember_pending(port, key)
    if not port then
        return
    end
    local set = pending[port]
    if not set then
        set = {}
        pending[port] = set
    end
    set[key] = true
end

local function fulfil_pending(port, id)
    if not port then
        return
    end
    local set = pending[port]
    if not set then
        return
    end
    for key in pairs(set) do
        tcp_sessions[key] = id
    end
    pending[port] = nil
end

local function expose(tree, pinfo, id)
    local subtree = tree:add(flow_proto, "Flow Association")
    subtree:add(flow_field, id)
    if pinfo.cols.custom then
        pinfo.cols.custom:set(id)
    elseif pinfo.cols.info then
        pinfo.cols.info:append(" [flow_id:" .. id .. "]")
    end
end

function flow_proto.dissector(_, pinfo, tree)
    local id

    if udp_field() then
        local key = session_key("udp", pinfo)
        id = udp_sessions[key]

        local info = data_field()
        if info then
            local parsed_id, port = parse_payload(info.range:bytes())
            if parsed_id then
                id = parsed_id
                udp_sessions[key] = parsed_id
                if port then
                    tcp_port_map[port] = parsed_id
                    fulfil_pending(port, parsed_id)
                end
            end
        end
    elseif tcp_field() then
        local key = session_key("tcp", pinfo)
        id = tcp_sessions[key]
        if not id then
            local src_port = tonumber(tostring(pinfo.src_port))
            local dst_port = tonumber(tostring(pinfo.dst_port))
            id = (src_port and tcp_port_map[src_port]) or (dst_port and tcp_port_map[dst_port])
            if id then
                tcp_sessions[key] = id
                fulfil_pending(src_port, id)
                fulfil_pending(dst_port, id)
            else
                remember_pending(src_port, key)
                remember_pending(dst_port, key)
            end
        end
    end

    if id then
        expose(tree, pinfo, id)
    end
end

register_postdissector(flow_proto)
