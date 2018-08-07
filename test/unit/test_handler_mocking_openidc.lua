local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()


function TestHandler:setUp()
  TestHandler.super:setUp()

  package.loaded["resty.openidc"] = nil
  self.module_resty = {openidc = {
    authenticate = function(...) return {}, nil end }
  }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end

  self.handler = require("kong.plugins.oidc.handler")()
end

function TestHandler:tearDown()
  TestHandler.super:tearDown()
end

function TestHandler:test_authenticate_ok_no_userinfo()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, false
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
end

function TestHandler:test_authenticate_ok_with_userinfo()
  self.module_resty.openidc.authenticate = function(opts)
    return {user = {sub = "sub"}}, false
  end
  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub")
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_authenticate_nok_no_recovery()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
end

function TestHandler:test_authenticate_nok_with_recovery()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true
  end

  self.handler:access({recovery_page_path = "x"})
  lu.assertTrue(self:log_contains("recovery page"))
end

function TestHandler:test_introspect_ok_no_userinfo()
  self.module_resty.openidc.introspect = function(opts)
    return false, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  self.handler:access({introspection_endpoint = "x"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
end

function TestHandler:test_introspect_ok_with_userinfo()
  self.module_resty.openidc.introspect = function(opts)
    return {}, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({introspection_endpoint = "x"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_bearer_only_with_good_token()
  local user = {
    active = true,
    client_id = "l238j323ds-23ij4",
    username = "jdoe",
    scope = "read write dolphin",
    sub = "Z5O3upPC88QrAjx00dis",
    aud = "https://protected.example.net/resource",
    iss = "https://server.example.com/",
    exp = 1419356238,
    iat = 1419350238,
    extension_field = "twenty-seven"
  }
  self.module_resty.openidc.introspect = function(opts)
    return user, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
  lu.assertEquals(headers["X-Credential-Scope"], user.scope)
  lu.assertEquals(headers["X-Credential-Client-ID"], user.client_id)
  lu.assertEquals(headers["X-Credential-Username"], user.username)
  lu.assertEquals(headers["X-Credential-Token-Type"], user.token_type)
  lu.assertEquals(headers["X-Credential-Exp"], user.exp)
  lu.assertEquals(headers["X-Credential-Iat"], user.iat)
  lu.assertEquals(headers["X-Credential-Nbf"], user.nbf)
  lu.assertEquals(headers["X-Credential-Sub"], user.sub)
  lu.assertEquals(headers["X-Credential-Aud"], user.aud)
  lu.assertEquals(headers["X-Credential-Iss"], user.iss)
  lu.assertEquals(headers["X-Credential-Jti"], user.jti)
end

function TestHandler:test_bearer_only_with_good_token_verify_subdomian_ok()
  local user = {
    active = true,
    sub = "eyJlbWFpbCI6ImZvb0BiYXIuY29tIiwic3ViZG9tYWluIjoic3BhbSJ9",
  }
  self.module_resty.openidc.introspect = function(opts)
    return user, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx", ["Host"] = "spam.test.com"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  ngx.decode_base64 = function(x)
    return '{"email":"foo@bar.com","subdomain":"spam"}'
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong", subject_verify_subdomain  = "yes"})
  lu.assertEquals(headers["X-Credential-Sub"], user.sub)
end

function TestHandler:test_bearer_only_with_good_token_verify_subdomian_nok()
  local user = {
    active = true,
    sub = "eyJlbWFpbCI6ImZvb0BiYXIuY29tIiwic3ViZG9tYWluIjoic3BhbSJ9",
  }
  self.module_resty.openidc.introspect = function(opts)
    return user, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx", ["Host"] = "eggs.test.com"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  ngx.decode_base64 = function(x)
    return '{"email":"foo@bar.com","subdomain":"spam"}'
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong", subject_verify_subdomain = "yes"})
  lu.assertEquals(headers["X-Credential-Sub"], nil)
end

function TestHandler:test_bearer_only_with_bad_token()
  self.module_resty.openidc.introspect = function(opts)
    return {}, "validation failed"
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong"})

  lu.assertEquals(ngx.header["WWW-Authenticate"], 'Bearer realm="kong",error="validation failed"')
  lu.assertEquals(ngx.status, ngx.HTTP_UNAUTHORIZED)
  lu.assertFalse(self:log_contains("introspect succeeded"))
end

lu.run()


