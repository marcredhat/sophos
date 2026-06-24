-- OCSF 1.3.0 serializer for Sophos XG Firewall logs. Maps Firewall logs to Network Activity (4001) and ATP/Anti-Virus to Detection Finding (2004). Preserves timestamp (ISO) and host for AISIEM.
function processEvent(event)

    --------------------------------------------------------------------------------
    -- HELPERS
    --------------------------------------------------------------------------------

    local function set_nested(obj, path, value)
        if value == nil or value == "" then return end
        local num = tonumber(value)
        if path:find("port$") or path:find("bytes") or path:find("packets") or path:find("uid$") then
            if num then value = num end
        end
        local keys = {}
        for k in path:gmatch("[^%.]+") do table.insert(keys, k) end
        local cur = obj
        for i = 1, #keys - 1 do
            if not cur[keys[i]] then cur[keys[i]] = {} end
            cur = cur[keys[i]]
        end
        cur[keys[#keys]] = value
    end

    local function map_severity(priority)
        if not priority then return 0 end
        local p = string.lower(tostring(priority))
        if p == "emergency"                        then return 6 end
        if p == "alert"                            then return 5 end
        if p == "critical"                         then return 5 end
        if p == "error"                            then return 4 end
        if p == "warning"                          then return 3 end
        if p == "notice"                           then return 2 end
        if p == "information" or p == "informational" then return 1 end
        if p == "debug"                            then return 1 end
        return 0
    end

    local function map_action(status, log_subtype)
        local s   = string.lower(tostring(status or ""))
        local sub = string.lower(tostring(log_subtype or ""))
        if s == "allow" or sub == "allowed" then return 1, "Allowed" end
        if s == "deny" or s == "drop" or sub == "denied" or sub == "drop" then return 2, "Denied" end
        return 99, "Other"
    end

    local function map_disposition(status)
        local s = string.lower(tostring(status or ""))
        if s == "allow" then return 1, "Allowed" end
        if s == "deny"  then return 2, "Blocked" end
        if s == "drop"  then return 6, "Dropped" end
        return 0, "Unknown"
    end

    local function map_status(status)
        local s = string.lower(tostring(status or ""))
        if s == "allow"            then return "Success", 1 end
        if s == "deny" or s == "drop" then return "Failure", 2 end
        return "Unknown", 0
    end

    --------------------------------------------------------------------------------
    -- MAIN TRANSFORM
    --------------------------------------------------------------------------------

    local function execute(e)
        local log_type     = e["log_type"] or ""
        local is_firewall  = (log_type == "Firewall")
        local is_detection = (log_type == "ATP" or log_type == "Anti-Virus")

        -- Determine OCSF class
        local class_uid, category_uid, type_uid, activity_id
        if is_firewall then
            class_uid    = 4001
            category_uid = 4
            activity_id  = 6       -- Traffic
            type_uid     = 400106
        elseif is_detection then
            class_uid    = 2004
            category_uid = 2
            activity_id  = 1       -- Create
            type_uid     = 200401
        else
            class_uid    = 4001
            category_uid = 4
            activity_id  = 0
            type_uid     = 400100
        end

        local action_id, action_name = map_action(e["status"], e["log_subtype"])
        local disp_id,   disp_name   = map_disposition(e["status"])
        local status_str, status_id  = map_status(e["status"])
        local severity_id            = map_severity(e["priority"])

        -- Build OCSF event
        local ocsf = {
            -- AISIEM required fields (root level)
            timestamp = e["timestamp"],   -- ISO string, required by AISIEM
            host      = e["host"],        -- required by AISIEM

            -- OCSF core classification
            class_uid     = class_uid,
            class_name    = is_firewall and "Network Activity" or "Detection Finding",
            category_uid  = category_uid,
            category_name = is_firewall and "Network Activity" or "Findings",
            type_uid      = type_uid,
            activity_id   = activity_id,
            time          = e["timestamp"],

            -- Severity & action
            severity_id   = severity_id,
            severity      = e["priority"],
            action_id     = action_id,
            action        = action_name,
            status        = status_str,
            status_id     = status_id,
            disposition_id = disp_id,
            disposition   = disp_name,

            -- Application
            app_name      = e["application"],

            -- Descriptive message
            message       = (log_type ~= "" and log_type or "Sophos XG") ..
                            " | " .. (e["log_subtype"] or "") ..
                            " | src=" .. (e["src_ip"] or "") ..
                            " dst=" .. (e["dst_ip"] or "") ..
                            " user=" .. (e["user_name"] or ""),

            -- Metadata
            metadata = {
                version     = "1.3.0",
                log_name    = e["log_type"],
                logged_time = e["timestamp"],
                product = {
                    vendor_name = "Sophos",
                    name        = "XG Firewall",
                    version     = e["device_name"],
                    uid         = e["device_id"]
                }
            },

            -- Device
            device = {
                hostname = e["host"],
                name     = e["device_name"],
                uid      = e["device_id"]
            },

            -- Actor
            actor = {
                user = { name = e["user_name"] }
            },

            unmapped = {}
        }

        -- Network endpoints (common to all log types)
        set_nested(ocsf, "src_endpoint.ip",             e["src_ip"])
        set_nested(ocsf, "src_endpoint.port",           e["src_port"])
        set_nested(ocsf, "src_endpoint.zone",           e["srczone"])
        set_nested(ocsf, "src_endpoint.interface.name", e["in_interface"])

        set_nested(ocsf, "dst_endpoint.ip",             e["dst_ip"])
        set_nested(ocsf, "dst_endpoint.port",           e["dst_port"])
        set_nested(ocsf, "dst_endpoint.zone",           e["dstzone"])
        set_nested(ocsf, "dst_endpoint.interface.name", e["out_interface"])

        set_nested(ocsf, "connection_info.protocol_name", e["protocol"])

        -- Firewall-specific
        if is_firewall then
            set_nested(ocsf, "traffic.bytes_out",   e["sent_bytes"])
            set_nested(ocsf, "traffic.bytes_in",    e["recv_bytes"])
            set_nested(ocsf, "traffic.packets_out", e["sent_pkts"])
            set_nested(ocsf, "traffic.packets_in",  e["recv_pkts"])

            set_nested(ocsf, "firewall_rule.uid",   e["fw_rule_id"])
            set_nested(ocsf, "firewall_rule.name",  e["fw_rule_name"])

            -- NAT fields (only if non-empty after fix transform)
            if e["tran_src_ip"] and e["tran_src_ip"] ~= "" then
                ocsf.unmapped.tran_src_ip   = e["tran_src_ip"]
                ocsf.unmapped.tran_src_port = e["tran_src_port"]
                ocsf.unmapped.tran_dst_ip   = e["tran_dst_ip"]
                ocsf.unmapped.tran_dst_port = e["tran_dst_port"]
            end

            ocsf.unmapped.application_risk       = e["application_risk"]
            ocsf.unmapped.application_technology = e["application_technology"]
            ocsf.unmapped.application_category   = e["application_category"]
            ocsf.unmapped.connevent              = e["connevent"]
            ocsf.unmapped.connid                 = e["connid"]
            ocsf.unmapped.hb_health              = e["hb_health"]
            ocsf.unmapped.nat_rule_id            = e["nat_rule_id"]
            ocsf.unmapped.policy_type            = e["policy_type"]
        end

        -- Detection-specific (ATP / Anti-Virus)
        if is_detection then
            local title = e["threatname"] or e["virus"] or e["event_type"] or "Unknown Threat"
            ocsf.finding_info = {
                title   = title,
                desc    = e["event_type"] or e["log_subtype"],
                uid     = e["log_id"],
                src_url = e["url"]
            }

            if e["virus"] then
                ocsf.malware = {{ name = e["virus"] }}
            end
            if e["threatname"] then
                ocsf.unmapped.threatname = e["threatname"]
            end
            if e["filename"] then
                ocsf.unmapped.filename   = e["filename"]
                ocsf.unmapped.quarantine = e["quarantine"]
            end
            if e["url"] then
                set_nested(ocsf, "url.url_string", e["url"])
                ocsf.unmapped.domain = e["domain"]
            end
            ocsf.unmapped.ep_uuid    = e["ep_uuid"]
            ocsf.unmapped.login_user = e["login_user"]
        end

        -- Common unmapped
        ocsf.unmapped.log_id        = e["log_id"]
        ocsf.unmapped.log_component = e["log_component"]
        ocsf.unmapped.log_subtype   = e["log_subtype"]
        ocsf.unmapped.timezone      = e["timezone"]
        ocsf.unmapped.facility      = e["facility"]
        ocsf.unmapped.source_ip     = e["source_ip"]

        return ocsf
    end

    --------------------------------------------------------------------------------
    -- SAFETY WRAPPER
    --------------------------------------------------------------------------------

    local ok, result = pcall(execute, event)
    if ok then
        return result
    else
        event["_ocsf_error"] = tostring(result)
        return event
    end
end
