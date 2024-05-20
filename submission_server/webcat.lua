local cjson = require("cjson")
local pgmoon = require("pgmoon")

local json_encode = cjson.encode
local json_decode = cjson.decode

local _M = {
    _DESCRIPTION = "WEBCAT API Server",
    _VERSION = '0.1',
}

-- POST     /api/v1/submission {domain, type} -> {id}
-- GET      /api/v1/submission -> {total_submissions}
-- GET      /api/v1/submission/<submission_id> -> {status, errors}

-- HTTP Response Helper
local function http_exit(json, status_code)
    ngx.status = status_code
    ngx.say(json_encode(json))
    ngx.exit(status_code)
end

-- PGSQL Helper
local function pg_init()
    local pg = pgmoon.new({
      host = "127.0.0.1",
      port = "5432",
      database = "webcat",
      user = "webcat",
      password = "jw8s0F4"
    })

    local err = pg:connect()
    if not err then
        ngx.log(ngx.ERR, "failed to connect to postgres: ", err)
        http_exit({status="KO"}, ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    return pg
end

-- JSON Body Helper
local function get_json_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local ok, json = pcall(json_decode, body)

    if ok and json then
        return json
    end

    http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
    return
end

-- Preliminary check
local function check_json_keys(json, keys)
    for _, key in ipairs(keys) do
        if not json[key] then
            http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
        end
    end
end


local function get_submission()
    local id = ngx.var.uri:gsub('.*%/', '')
    id = tonumber(id)

    local pg = pg_init()

    if not id then
        -- Return stats
        local res, err = pg:query("SELECT COUNT(id) as total_submissions FROM submissions")
        local total_submissions = res[1]["total_submissions"]
        http_exit({status="OK", total_submissions=total_submissions}, ngx.HTTP_OK)
    end

    local res, err = pg:query("SELECT id, submitted_fqdn, fqdn, type_id, timestamp, status_id, status_timestamp, (select value from types where id = submissions.type_id) as type_value, (select value from statuses where id = submissions.status_id) as status_value FROM submissions WHERE id = " .. pg:escape_literal(id))

    -- If there is no record, return a 404 status code
    if #res ~= 1 then
        http_exit({status="KO"}, ngx.HTTP_NOT_FOUND)
    end

    local submission = res[1]

    local res, err = pg:query("SELECT status_id, timestamp FROM status_changes WHERE submission_id = " .. pg:escape_literal(submission["id"]))

    http_exit({status="OK", id=submission["id"],
                            fqdn=submission["fqdn"],
                            type=submission["type_value"],
                            status=submission["status_value"],
                            log=res
              }, ngx.HTTP_OK)
end

local function post_submission()
    local json = get_json_body()

    -- Check that all JSON keys are there
    check_json_keys(json, {"fqdn", "type"})

    -- Parse the domain and the action requested from the json request
    local fqdn_input = json["fqdn"]
    local type_input = json["type"]

    local pg = pg_init()

    -- Convert the type keyword to a numerical id
    local res, err = pg:query("SELECT id FROM types WHERE value = " .. pg:escape_literal(type_input))

    -- Type is not valid
    if not res then
        ngx.say(err)
        http_exit({status="KO"}, ngx.HTTP_BAD_REQUEST)
    end

    type_id = res[1]["id"]

    local res, err = pg:query("INSERT INTO submissions (submitted_fqdn, type_id) VALUES (" .. pg:escape_literal(fqdn_input) .. ", " .. pg:escape_literal(type_id) ..  ") RETURNING id;")

    if err ~= 1 then
        ngx.log(ngx.ERR, "failed to insert into submissions: ", err)
        http_exit({status="KO"}, ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    submission_id = res[1]["id"]

    http_exit({status="OK", id=submission_id}, ngx.HTTP_OK)
end

-- Request handler /
function _M.index()
    if ngx.req.get_method() == "GET" then
        get_submission()
    elseif ngx.req.get_method() == "POST" then
        post_submission()
    else
        http_exit({status="KO"}, ngx.HTTP_NOT_ALLOWED)
    end
    return
end

return _M
