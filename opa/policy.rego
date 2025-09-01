package envoy.authz

default allow := false

# 1) Authorization: Bearer 토큰 추출
bearer_token := t if {
  auth := input.attributes.request.http.headers["authorization"]
  auth != ""
  parts := split(auth, " ")
  count(parts) == 2
  lower(parts[0]) == "bearer"
  t := parts[1]
}

# 2) Keycloak 인트로스펙션 (active만 확인, 2s)
introspection := resp if {
  tok := bearer_token
  resp := http.send({
    "method": "POST",
    "url": "http://keycloak:8080/realms/zerotrust/protocol/openid-connect/token/introspect",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "raw_body": sprintf("client_id=%v&client_secret=%v&token=%v",
      [data.keycloak.client_id, data.keycloak.client_secret, tok]),
    "timeout": "5s"
  })
}

# 3) 토큰 활성 (object / string(JSON) 모두 대응)
active if {
  introspection.status_code == 200
  is_object(introspection.body)
  object.get(introspection.body, "active", false) == true
}
active if {
  introspection.status_code == 200
  is_string(introspection.body)
  json.unmarshal(introspection.body).active == true
}

# 4) 위협 인텔: 차단 IP
blocked_ip if { input.attributes.source.address == data.ti.block_ips[_] }

# 5) 메서드 → 필요 스코프
method := m if { m := input.attributes.request.http.method }

write_method if { method == "POST" }
write_method if { method == "PUT" }
write_method if { method == "DELETE" }
write_method if { method == "PATCH" }

required_scope := "write" if { write_method }
required_scope := "read"  if { not write_method }

# 6) JWT claims / 인트로스펙션에서 scope 후보값 구하기
claims := c if {
  t := bearer_token
  parts := io.jwt.decode(t)
  c := parts[1]            # payload
}
scope_from_claims := s if {
  is_object(claims)
  v := object.get(claims, "scope", "")
  s := sprintf("%v", [v])
}
scope_from_introspect_obj := s if {
  is_object(introspection.body)
  v := object.get(introspection.body, "scope", "")
  s := sprintf("%v", [v])
}
scope_from_introspect_str := s if {
  is_string(introspection.body)
  v := object.get(json.unmarshal(introspection.body), "scope", "")
  s := sprintf("%v", [v])
}

# 7) 단 하나의 scope_str만 선택 (우선순위: JWT → 인트로스펙트 object → string)
scope_str := s if {
  scope_from_claims = s
  s != ""
} else := s if {
  scope_from_introspect_obj = s
  s != ""
} else := s if {
  scope_from_introspect_str = s
  s != ""
} else := s if {
  s := ""                  # 전부 비었을 때
}

# 8) required_scope 포함 여부(경계 매칭)
has_required_scope if {
  rs := required_scope
  ss := sprintf(" %v ", [scope_str])
  needle := sprintf(" %v ", [rs])
  contains(ss, needle)
}

# 9) 디버그 트레이스
trace if {
  print(sprintf("OPA TRACE active=%v method=%v required=%v scope_str='%v'",
    [active, method, required_scope, scope_str]))
}

# 10) 디버그 토글 (data.json에서 온/오프)
skip_active if { data.debug.skip_active_check == true }
skip_scope  if { data.debug.skip_scope_check  == true }

active_ok if { skip_active }
active_ok if { active }

scope_ok if { skip_scope }
scope_ok if { has_required_scope }

# 11) 최종 승인
allow if {
  trace
  active_ok
  not blocked_ip
  scope_ok
}

