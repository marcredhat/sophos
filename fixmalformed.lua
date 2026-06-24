-- Fixes malformed tran_src_ip, tran_src_port, tran_dst_ip, tran_dst_port fields caused by empty values in Sophos XG KV parsing
function processEvent(event)
  local ok, err = pcall(function()
    -- The KV parser merges empty-value fields with the next key.
    -- e.g. tran_src_ip gets value "tran_src_port=0" instead of ""
    -- We fix this by detecting and splitting such merged values.

    local fields_to_fix = {
      "tran_src_ip",
      "tran_src_port",
      "tran_dst_ip",
      "tran_dst_port"
    }

    for _, field in ipairs(fields_to_fix) do
      local val = event[field]
      if val ~= nil then
        local str_val = tostring(val)
        -- Check if the value contains an embedded key=value pair (e.g. "tran_src_port=0")
        local embedded_key, embedded_val = str_val:match("^([%w_]+)=(.*)$")
        if embedded_key then
          -- The current field had an empty value; set it to empty string
          event[field] = ""
          -- Set the embedded key to its parsed value (convert to number if possible)
          local num = tonumber(embedded_val)
          event[embedded_key] = num ~= nil and num or embedded_val
        else
          -- Value is fine; convert numeric strings to numbers where appropriate
          local num = tonumber(str_val)
          if num ~= nil then
            event[field] = num
          end
        end
      end
    end
  end)

  if not ok then
    event["_lua_error"] = tostring(err)
  end

  return event
end
