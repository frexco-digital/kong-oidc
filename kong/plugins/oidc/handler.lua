local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  if oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)
    if response then
      utils.injectUser(response)
    end
  end

  if response == nil then
    response = make_oidc(oidcConfig)
    if response then
      if (response.user) then
        utils.injectUser(response.user)
      end
      if (response.access_token) then
        utils.injectAccessToken(response.access_token)
      end
      if (response.id_token) then
        utils.injectIDToken(response.id_token)
      end
    end
  end
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function introspect(oidcConfig)
  local unauthorized_response = utils.get_unauthorized_response('token-invalid')
  if not utils.has_bearer_access_token() then
    utils.exit(ngx.HTTP_UNAUTHORIZED, unauthorized_response, ngx.HTTP_UNAUTHORIZED)
  end

  if utils.verify_token_expired() then
    local json_response = utils.get_unauthorized_response('token-expired')
    utils.exit(ngx.HTTP_UNAUTHORIZED, json_response, ngx.HTTP_UNAUTHORIZED)
  end

  -- Service token verification
  if utils.is_ms_token() then
    if not oidcConfig.verify_ms_token then
      if not utils.verify_signature(oidcConfig.token_public_key) then
        utils.exit(ngx.HTTP_UNAUTHORIZED, unauthorized_response, ngx.HTTP_UNAUTHORIZED)
      end
      ngx.log(ngx.ALERT, '### SKIPPING REQUEST ###')
      return utils.claims
    end
  end

  -- Client token verification
  if not utils.is_ms_token() then
    local keycloak_token_is_valid = utils.verify_signature(oidcConfig.token_public_key)
    local ameixa_token_is_valid = utils.verify_signature(oidcConfig.token_private_key)
    if not oidcConfig.verify_client_token then
      if not keycloak_token_is_valid and not ameixa_token_is_valid then
        utils.exit(ngx.HTTP_UNAUTHORIZED, unauthorized_response, ngx.HTTP_UNAUTHORIZED)
      end
      ngx.log(ngx.ALERT, '### SKIPPING REQUEST ###')
      return utils.claims
    end
    if ameixa_token_is_valid then
      ngx.log(ngx.ALERT, '### SKIPPING REQUEST ###')
      return utils.claims
    end
    if not keycloak_token_is_valid then
      utils.exit(ngx.HTTP_UNAUTHORIZED, unauthorized_response, ngx.HTTP_UNAUTHORIZED)
    end
  end

  if oidcConfig.bearer_only == "yes" then
    ngx.log(ngx.ALERT, '### MAKING REQUEST ###')
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, unauthorized_response, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil

end


return OidcHandler
