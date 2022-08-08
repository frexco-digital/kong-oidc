local cjson = require("cjson")
local openssl_hmac = require "resty.openssl.hmac"

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

function M.get_redirect_uri_path(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      return path
    elseif path == "/" then
      return "/cb"
    elseif path:sub(-1) == "/" then
      return path:sub(1, -2)
    else
      return path .. "/"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    introspection_endpoint = config.introspection_endpoint,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri_path = config.redirect_uri_path or M.get_redirect_uri_path(ngx),
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters(config.filters),
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
    verify_client_token = config.verify_client_token,
    client_token_public_key = config.client_token_public_key
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken)
  ngx.req.set_header("X-Access-Token", accessToken)
end

function M.injectIDToken(idToken)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header("X-ID-Token", ngx.encode_base64(tokenStr))
end

function M.injectUser(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.ctx.authenticated_credential = tmp_user
  local userinfo = cjson.encode(user)
  ngx.req.set_header("X-Userinfo", ngx.encode_base64(userinfo))
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(divider+1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

local alg_sign = {
  HS256 = function(data, key) return openssl_hmac.new(key, "sha256"):final(data) end
}

local alg_verify = {
  HS256 = function(data, signature, key) return signature == alg_sign.HS256(data, key) end
}

local function base64_decode(input)
  local remainder = #input % 4

  if remainder > 0 then
    local padlen = 4 - remainder
    input = input .. string.rep("=", padlen)
  end

  input = input:gsub("-", "+"):gsub("_", "/")
  return ngx.decode_base64(input)
end


local function tokenize(str, div, len)
  local result, pos = {}, 0

  local iter = function()
    return string.find(str, div, pos, true)
  end

  for st, sp in iter do
    result[#result + 1] = string.sub(str, pos, st-1)
    pos = sp + 1
    len = len - 1
    if len <= 1 then
      break
    end
  end

  result[#result + 1] = string.sub(str, pos)
  return result
end


local function decode_token(token)

  local header_64, claims_64, signature_64 = unpack(tokenize(token, ".", 3))

  local ok, header, claims, signature = pcall(function()
    return cjson.decode(base64_decode(header_64)),
           cjson.decode(base64_decode(claims_64)),
           base64_decode(signature_64)
  end)

  return {
    token = token,
    header_64 = header_64,
    claims_64 = claims_64,
    signature_64 = signature_64,
    header = header,
    claims = claims,
    signature = signature
  }
end


function GetRoles(header)
  local token_64 = header:sub(header:find(' ')+1)
  local payload = decode_token(token_64)
  for k, v in pairs(payload.claims.realm_access.roles) do
    ngx.log(ngx.WARN, tostring(k))
    ngx.log(ngx.WARN, tostring(v))
  end
  local roles = nil
  -- local roles = payload.claims.realm_access.roles
  -- ngx.log(ngx.WARN, tostring(roles))
  -- if roles == nil then return {} end
  return roles
end

function M.is_client_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local roles = GetRoles(header)
    if roles == nil then return false end
    for role in roles do
      if string.lower(role) == 'client' then
        return true
      end
    end
  end
  return false
end


return M
