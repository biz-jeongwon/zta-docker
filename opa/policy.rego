package envoy.authz

default allow = false

# Extract Bearer token from Authorization header
get_token(t) {
  auth := input.attributes.request.http.headers["authorization"]
  parts := split(auth, " ")
  count(parts) == 2
  lower(parts[0]) == "bearer"
  t := parts[1]
}

# Introspect the token at Keycloak (confidential client)
introspection := resp {
  some t
  get_token(t)
  resp := http.send({
    "method": "POST",
    "url": "http://keycloak:8080/realms/zerotrust/protocol/openid-connect/token/introspect",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "raw_body": sprintf("client_id=%v&client_secret=%v&token=%v", [data.keycloak.client_id, data.keycloak.client_secret, t]),
    "timeout": "0.5s"
  })
}

active {
  introspection.status_code == 200
  introspection.body.active == true
}

# Basic IP blocklist fed by a PIP (threat intel)
blocked_ip {
  input.attributes.source.address == data.ti.block_ips[_]
}

method := input.attributes.request.http.method

# Map HTTP method to required scope
required_scope := s {
  s := "read"
  not write_method
}
required_scope := s {
  s := "write"
  write_method
}
write_method { method == "POST" }
write_method { method == "PUT" }
write_method { method == "DELETE" }
write_method { method == "PATCH" }

scopes := split(introspection.body.scope, " ")

has_scope(s) {
  scopes[_] == s
}

# Final decision: token must be active, IP not blocked, scope satisfied
allow {
  active
  not blocked_ip
  has_scope(required_scope)
}
