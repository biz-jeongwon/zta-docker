package envoy.authz

default allow := false

# Authorization 헤더에서 Bearer 토큰 추출 (출력값 규칙)
bearer_token := t if {
  auth := input.attributes.request.http.headers["authorization"]
  auth != ""
  parts := split(auth, " ")
  count(parts) == 2
  lower(parts[0]) == "bearer"
  t := parts[1]
}

# Keycloak 인트로스펙션
introspection := resp if {
  tok := bearer_token
  resp := http.send({
    "method": "POST",
    "url": "http://keycloak:8080/realms/zerotrust/protocol/openid-connect/token/introspect",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "raw_body": sprintf("client_id=%v&client_secret=%v&token=%v",
      [data.keycloak.client_id, data.keycloak.client_secret, tok]),
    "timeout": "0.5s"
  })
}

# 토큰이 활성 상태인가?
active if {
  introspection.status_code == 200
  introspection.body.active == true
}

# 위협 인텔: 차단 IP
blocked_ip if {
  input.attributes.source.address == data.ti.block_ips[_]
}

# HTTP 메서드와 필요 scope 매핑
method := input.attributes.request.http.method

required_scope := "read" if { not write_method }
required_scope := "write" if { write_method }
write_method if { method == "POST" }
write_method if { method == "PUT" }
write_method if { method == "DELETE" }
write_method if { method == "PATCH" }

# 토큰의 scope 목록
scopes := split(introspection.body.scope, " ")

has_scope(s) if { scopes[_] == s }

# 최종 승인
allow if {
  active
  not blocked_ip
  has_scope(required_scope)
}

