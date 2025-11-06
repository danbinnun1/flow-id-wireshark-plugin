-- Flow ID tracking post-dissector for Wireshark
--
-- This plugin inspects UDP packets for metadata messages that contain a
-- flow identifier and the TCP port associated with the same logical flow.
-- The discovered mapping is then applied to every packet that belongs to the
-- corresponding UDP or TCP session and exposed through a custom protocol
-- field (flowid.id). The field can be promoted to a column in Wireshark to
-- visualise the flow identifier directly in the packet list. When no custom
-- column is configured the plugin appends the identifier to the Info column
-- so the association is still visible during analysis.
--
-- Metadata payload format (ASCII):
--   flow_id=<uuid>;tcp_port=<port>
-- Additional key/value pairs are ignored. Only the flow identifier is
-- required; the TCP port is optional but enables the plugin to associate the
-- corresponding TCP stream automatically.

local flow_proto = Proto("flowid", "Flow ID Tracker")

local flow_field = ProtoField.string("flowid.id", "Flow ID")
local source_field = ProtoField.string("flowid.source", "Flow Source")
flow_proto.fields = { flow_field, source_field }

local udp_field = Field.new("udp")
local tcp_field = Field.new("tcp")
local data_field = Field.new("data.data")

local udp_sessions = {}
local tcp_sessions = {}
local tcp_port_map = {}

local function shell_escape(str)
    local value = tostring(str or "")
    return "'" .. value:gsub("'", "'\"'\"'") .. "'"
end

local function get_python_script_path()
    local info = debug.getinfo(get_python_script_path, "S")
    if info and info.source and info.source:sub(1, 1) == "@" then
        local source_path = info.source:sub(2)
        local directory = source_path:match("(.*[/\\])")
        if directory then
            return directory .. "../scripts/parse_metadata.py"
        end
    end
    return "scripts/parse_metadata.py"
end

local python_script_path = get_python_script_path()

local function normalise_session(proto, src, sport, dst, dport)
    local addr_a = tostring(src)
    local addr_b = tostring(dst)
    local port_a = tonumber(tostring(sport)) or 0
    local port_b = tonumber(tostring(dport)) or 0

    if addr_a > addr_b or (addr_a == addr_b and port_a > port_b) then
        addr_a, addr_b = addr_b, addr_a
        port_a, port_b = port_b, port_a
    end

    return string.format("%s:%s:%d-%s:%d", proto, addr_a, port_a, addr_b, port_b)
end

local function bytearray_to_string(bytearray)
    if not bytearray then
        return nil
    end
    return bytearray:raw(0, bytearray:len())
end

local function parse_metadata(payload)
    if not payload or payload == "" then
        return nil, nil
    end

    local command = string.format("python3 %s %s", shell_escape(python_script_path), shell_escape(payload))
    local handle = io.popen(command)
    if not handle then
        return nil, nil
    end

    local output = handle:read("*a") or ""
    handle:close()

    local flow_id_line, tcp_port_line = output:match("^([^\n]*)\n([^\n]*)")
    if not flow_id_line then
        flow_id_line = output:match("^([^\n]*)") or ""
        tcp_port_line = ""
    end

    flow_id_line = flow_id_line:match("^%s*(.-)%s*$") or ""
    tcp_port_line = tcp_port_line:match("^%s*(.-)%s*$") or ""

    if flow_id_line == "" then
        return nil, nil
    end

    local flow_id = flow_id_line
    local tcp_port = nil
    if tcp_port_line ~= "" then
        tcp_port = tonumber(tcp_port_line)
    end

    return flow_id, tcp_port
end

function flow_proto.dissector(tvb, pinfo, tree)
    local flow_id = nil
    local source = nil

    if udp_field() then
        local session_key = normalise_session("udp", pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)
        flow_id = udp_sessions[session_key]
        if flow_id then
            source = "udp session cache"
        end

        local data_info = data_field()
        if data_info then
            local payload = bytearray_to_string(data_info.range:bytes())
            local parsed_id, tcp_port = parse_metadata(payload)
            if parsed_id then
                flow_id = parsed_id
                source = "udp metadata"
                udp_sessions[session_key] = parsed_id
                if tcp_port then
                    tcp_port_map[tcp_port] = parsed_id
                end
            end
        end
    elseif tcp_field() then
        local session_key = normalise_session("tcp", pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)
        flow_id = tcp_sessions[session_key]
        if flow_id then
            source = "tcp session cache"
        else
            local src_port = tonumber(tostring(pinfo.src_port))
            local dst_port = tonumber(tostring(pinfo.dst_port))
            if src_port and tcp_port_map[src_port] then
                flow_id = tcp_port_map[src_port]
                source = "tcp port map"
            elseif dst_port and tcp_port_map[dst_port] then
                flow_id = tcp_port_map[dst_port]
                source = "tcp port map"
            end
            if flow_id then
                tcp_sessions[session_key] = flow_id
            end
        end
    end

    if flow_id then
        local subtree = tree:add(flow_proto, "Flow Association")
        subtree:add(flow_field, flow_id)
        if source then
            subtree:add(source_field, source)
        end

        if pinfo.cols.custom then
            pinfo.cols.custom:set(flow_id)
        elseif pinfo.cols.info then
            pinfo.cols.info:append(" [flow_id:" .. flow_id .. "]")
        end
    end
end

register_postdissector(flow_proto)
