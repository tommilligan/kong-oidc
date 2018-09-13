local cjson = require("cjson")

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
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    subject_verify_subdomain = config.subject_verify_subdomain,
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
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectUser(user, subject_verify_subdomain)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.ctx.authenticated_credential = tmp_user
  local userinfo = cjson.encode(user)
  ngx.req.set_header("X-Userinfo", ngx.encode_base64(userinfo))

  -- verify subdomain from subject
  -- against host header
  if subject_verify_subdomain == "yes" then
    local host = ngx.req.get_headers()['Host']
    local host_subdomain = string.match(host, "[^%.]+")
    local subject = cjson.decode(ngx.decode_base64(user.sub))
    if host_subdomain ~= subject.subdomain then
      ngx.log(ngx.DEBUG, "subject/host mismatch; subject: " .. subject.subdomain .. ", host: " .. host)
      return M.exit(ngx.HTTP_UNAUTHORIZED, "invalid token", ngx.HTTP_UNAUTHORIZED)
    end
    ngx.log(ngx.DEBUG, "subject/host verified; subject: " .. subject.subdomain .. ", host: " .. host)
  end

  -- also set Kong defined X-Credential headers
  -- for compaibility with their oauth2-introspection plugin
  -- https://docs.konghq.com/enterprise/0.33-x/plugins/oauth2-introspection/
  ngx.req.set_header("X-Credential-Scope", user.scope)
  ngx.req.set_header("X-Credential-Client-ID", user.client_id)
  ngx.req.set_header("X-Credential-Username", user.preferred_username)
  ngx.req.set_header("X-Credential-Token-Type", user.token_type)
  ngx.req.set_header("X-Credential-Exp", user.exp)
  ngx.req.set_header("X-Credential-Iat", user.iat)
  ngx.req.set_header("X-Credential-Nbf", user.nbf)
  ngx.req.set_header("X-Credential-Sub", user.sub)
  ngx.req.set_header("X-Credential-Aud", user.aud)
  ngx.req.set_header("X-Credential-Iss", user.iss)
  ngx.req.set_header("X-Credential-Jti", user.jti)
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

return M
