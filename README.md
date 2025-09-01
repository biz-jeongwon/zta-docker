# Zero Trust Architecture (ZTA) – Docker Starter

간단한 **제로트러스트 아키텍처** 데모입니다.  
Envoy(PEP) ↔ OPA(PDP) ↔ Keycloak(PIP) 조합으로 **토큰·스코프 기반 인가**를 수행하고, 보호 리소스(Flask)는 **정책 앞단에서** 보호합니다.

---

## 구성요소(What each does)

- **OPA (Open Policy Agent)**  
  정책을 **Rego**로 작성해 요청을 평가하는 **정책 엔진(PDP)**.  
  Envoy에서 받은 컨텍스트와 Keycloak 인트로스펙션 결과, `data.json`의 위협 인텔(차단 IP 등)을 종합해 **allow/deny** 결정을 반환합니다.

- **Keycloak**  
  오픈소스 **IAM/IdP**. 사용자 인증, 클라이언트/스코프 관리, **OIDC 토큰 발급/검증**(인트로스펙션)을 담당하는 **PIP** 입니다.

- **Envoy**  
  L4/L7 프록시(게이트웨이). 모든 트래픽의 **문지기(PEP)** 로서, 외부 권한판단(OPA) 결과가 **allow**일 때만 백엔드(Flask)로 프록시합니다.

- **Flask**  
  보호 대상 **Resource(업무 서비스)**. 인증/인가는 Envoy+OPA 앞단에서 처리되므로 앱 로직은 깔끔하게 유지됩니다.

---

## 아키텍처(요약)

```
Client --(Bearer token)--> Envoy(PEP) --ext_authz(gRPC)--> OPA(PDP)
                                   ^                         |
                                   |<----- introspect -------|
                                   |          Keycloak(PIP)
                    allow -> Flask(Resource)      |
                    deny  -> 403                  | users, clients, scopes
```

- **스코프 규칙(예시)**  
  - `GET` → `read` 필요  
  - `POST/PUT/PATCH/DELETE` → `write` 필요  
  - `data.json` 의 `ti.block_ips` 에 포함된 IP는 즉시 거부  
  - 토큰 `active=false` 면 거부

---

## 폴더 구조

```
.
├─ app/
│  └─ app.py                  # 데모 Flask 앱
├─ envoy/
│  └─ envoy.yaml              # Envoy 설정 (ext_authz → OPA)
├─ opa/
│  ├─ policy.rego             # Rego 정책
│  ├─ data.json               # 인텔/설정 (client_secret, block_ips 등)
│  └─ config.yaml             # OPA 서버/플러그인 설정
└─ docker-compose.yml
```

---

## 빠른 시작

### 0) 사전 준비
- **Docker Desktop** 설치 (Windows / macOS)
- macOS(Apple Silicon, ARM) 사용 시 **이미지 아키텍처**를 amd64로 고정 권장:
  ```bash
  export DOCKER_DEFAULT_PLATFORM=linux/amd64
  ```
  `docker-compose.yml` 의 Envoy 이미지는 호환 태그 사용:
  ```yaml
  image: envoyproxy/envoy:tools-dev-f384ab2b3e3aa0564ef25f57dc2ed8ad61eaf0cb
  ```

### 1) 컨테이너 기동
```bash
docker compose up -d --build
```

> Windows(WSL2)·macOS 모두 지원. 처음 실행 시 이미지 pull/빌드로 시간이 소요될 수 있습니다.

### 2) Keycloak 초기화
1. 브라우저에서 **http://localhost:8081** 접속 → `admin` / `admin` 로그인  
2. **Realm 생성**: `zerotrust`
3. **Client Scope 생성**  
   - `read`, `write` 생성  
   - 각 스코프의 **Include in token scope = ON**
4. **Clients 생성**
   - `demo-app` (Public)
     - *Capability config*:  
       - **Client authentication = OFF**  
       - **Standard flow = OFF**  
       - **Direct access grants = ON**
     - *Client Scopes*: `read`, `write` (Optional 로 추가)
   - `opa-introspect` (Confidential)
     - *Capability config*:  
       - **Client authentication = ON**  
       - **Standard flow = OFF**  
       - **Direct access grants = OFF**
     - **Credentials 탭**에서 **Client Secret** 복사
5. **사용자 생성**
   - `Users → Add user` 에서 `alice`, `bob`
   - 각 사용자 **Credentials** 에서 비밀번호 설정 (Temporary **OFF**)
6. **Required Actions 비활성화**  
   - `Authentication → Required actions` 메뉴에서 전부 **Disabled**

### 3) OPA 설정(인트로스펙션 비밀키 반영)
- 복사한 `opa-introspect` 의 **Client Secret** 을 `opa/data.json` 에 입력:
  ```json
  {
    "keycloak": {
      "client_id": "opa-introspect",
      "client_secret": "<복사한 secret>"
    },
    "ti": {
      "block_ips": []
    }
  }
  ```
- OPA 재시작
  ```bash
  docker compose restart opa
  ```

### 4) 토큰 발급 & 리소스 호출 (도커 네트워크 내부 기준)
**중요:** 컨테이너에서 보는 Keycloak 주소는 `keycloak:8080` 입니다.
```bash
# 토큰 발급 (alice, read+write 스코프)
TOKEN=$(docker run --rm --network zta-docker_default curlimages/curl:8.8.0 -s \
  -X POST 'http://keycloak:8080/realms/zerotrust/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&client_id=demo-app&username=alice&password=alice&scope=read+write' \
  | jq -r .access_token)

# GET /
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/

# POST /write
curl -i -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"x":1}' http://localhost:8080/write
```

> **200 OK** 가 나오면 정상. 403 이면 아래 **문제 해결**을 참고하세요.

---

## 문제 해결(Troubleshooting)

### 403이 계속 뜰 때 체크리스트
1. **토큰에 스코프 포함?**  
   - 인트로스펙션에서 `scope` 에 `read`/`write` 가 보여야 합니다.
   ```bash
   SECRET=$(jq -r .keycloak.client_secret opa/data.json)
   docker run --rm --network zta-docker_default -e TOKEN="$TOKEN" -e SECRET="$SECRET" \
     curlimages/curl:8.8.0 -s \
     -X POST 'http://keycloak:8080/realms/zerotrust/protocol/openid-connect/token/introspect' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d "client_id=opa-introspect&client_secret=$SECRET&token=$TOKEN" | jq '{active,scope}'
   ```
2. **토큰 발급/검증 주소 일치?**  
   - 컨테이너 내부에서는 **`keycloak:8080`** 으로 발급·검증해야 `active:true`.  
     (호스트 `localhost:8081` 로 발급한 토큰을 컨테이너에서 검증하면 **active:false** 가 될 수 있음)
3. **Required Actions 미해제 이슈**  
   - Keycloak `Authentication → Required actions` 가 **Disabled** 인지 확인.
4. **메서드 ↔ 스코프 매핑 문제**  
   - `GET` 은 `read`, `POST`/`PUT`/`PATCH`/`DELETE` 는 `write` 필요.
5. **차단 IP**  
   - `opa/data.json` 의 `ti.block_ips` 에 본인 IP가 들어있지 않은지 확인.
6. **OPA 정책/로그 확인**  
   - `docker compose logs -f opa` 로 **Decision Log** 에서 deny 사유 확인.

### macOS(ARM)에서 Envoy 실행 문제
- `bss_size overflow` 등 Rosetta 관련 에러 시:
  - `export DOCKER_DEFAULT_PLATFORM=linux/amd64`
  - `envoyproxy/envoy:tools-dev-<sha>` 호환 태그 사용(본문 “빠른 시작” 참고)

---

## 포트 표

| 컴포넌트 | 컨테이너 내부 | 호스트 노출 | 용도 |
| --- | --- | --- | --- |
| Keycloak | `:8080` | `localhost:8081` | Admin/토큰/인트로스펙션 |
| Envoy | `:8080` | `localhost:8080` | 게이트웨이 엔드포인트 |
| Envoy Admin | `:9901` | `localhost:9901` | 상태/統計 |
| OPA gRPC | `:9191` | `localhost:9191` | Envoy ext_authz |
| OPA REST | `:8181` | `localhost:8181` | 디버깅/데이터 조회(옵션) |
| Flask | `:5000` | (예: `localhost:5001`) | 보호 리소스(백엔드) |

---

Created with Chatgpt 5 Thinking
