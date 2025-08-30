# ZTA Docker Starter

Minimal Zero Trust Architecture with Docker Compose mapping to the PDP/PEP/PIP model.

## Services
- **Keycloak** (ID 관리, 토큰 발급; `http://localhost:8081`)
- **OPA** (PE: 정책 엔진) + Envoy ext_authz gRPC
- **Envoy** (PEP: 게이트웨이/세션 접속 제어; `http://localhost:8080`)
- **Demo App** (보호되는 리소스; Flask, `/`와 `/write` 제공)

## Quick start
```bash
docker compose up -d --build
```

### Keycloak 초기 설정 (한 번만)
1) `http://localhost:8081` 접속 → `admin/admin` 로그인.
2) Realm 생성: **zerotrust**.
3) Client 생성 (Public): **demo-app**. 유효한 Redirect URI에 `http://localhost/*` 정도 등록(테스트에는 불필요).
4) Client 생성 (Confidential): **opa-introspect** → `Service accounts enabled` 켜기 → 생성된 **Client secret**를 복사.
5) `opa/data.json`의 `"keycloak.client_secret"` 값을 위에서 복사한 값으로 바꾸고 OPA를 재시작하세요.
   ```bash
   docker compose restart opa
   ```
6) Realm Roles 만들기: `read`, `write` (필요시 `admin`).
7) 사용자 추가: 예) `alice`(read, write), `bob`(read).
   - 비밀번호 설정(Temporary 해제).

### 토큰 발급 (패스워드 그랜트로 간단 테스트)
```bash
# alice (read,write)
TOKEN=$(curl -s -X POST "http://localhost:8081/realms/zerotrust/protocol/openid-connect/token"   -H "Content-Type: application/x-www-form-urlencoded"   -d "grant_type=password&client_id=demo-app&username=alice&password=alice&scope=read write" | jq -r .access_token)

# bob (read only)
TOKEN_RO=$(curl -s -X POST "http://localhost:8081/realms/zerotrust/protocol/openid-connect/token"   -H "Content-Type: application/x-www-form-urlencoded"   -d "grant_type=password&client_id=demo-app&username=bob&password=bob&scope=read" | jq -r .access_token)
```

### 접근 테스트
```bash
# 허용: read scope로 GET
curl -i -H "Authorization: Bearer $TOKEN_RO" http://localhost:8080/

# 거부: write scope 없이 POST
curl -i -X POST -H "Authorization: Bearer $TOKEN_RO" -H "Content-Type: application/json"      -d '{"x":1}' http://localhost:8080/write

# 허용: write scope로 POST
curl -i -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"      -d '{"x":1}' http://localhost:8080/write
```

### 위협 인텔리전스(간단 차단 목록) 업데이트
`opa/data.json`의 `ti.block_ips`에 차단할 IP를 넣고 OPA를 재시작하면 즉시 반영됩니다.
```json
{ "ti": { "block_ips": ["127.0.0.1"] } }
```

---

## 매핑
- **PDP/PE**: OPA(정책 엔진) – Rego 정책(`opa/policy.rego`)
- **PA**: Keycloak의 토큰 발급/세션 관리 (PEP에 간접적으로 영향)
- **PEP**: Envoy 게이트웨이(`envoy.yaml`, ext_authz → OPA)
- **PIP**: 
  - ID 관리 → Keycloak
  - 규제/내부규정/데이터 접근 정책 → Rego 규칙
  - 위협 인텔 → `data.json`의 차단 목록(예시)
  - 로그/모니터링 → Envoy 접근 로그(추가로 Loki/ELK 연동 가능)

> 데모이므로 비밀번호 그랜트와 간단 스코프를 사용했습니다. 실제 운영에서는 PKCE/OIDC 코드 플로우, 디바이스/네트워크 신뢰도, 세션 수명/재평가, 감사 로그 및 SIEM 연계를 적용하세요.
