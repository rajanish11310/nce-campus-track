from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from datetime import date
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-production")
DB = os.environ.get("DATABASE_PATH", "campustrack.db")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS students(
      roll TEXT PRIMARY KEY, name TEXT NOT NULL, branch TEXT, semester TEXT,
      phone TEXT, email TEXT, subject TEXT, notes TEXT
    );
    CREATE TABLE IF NOT EXISTS attendance(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      roll TEXT NOT NULL REFERENCES students(roll) ON DELETE CASCADE,
      day TEXT NOT NULL, subject TEXT NOT NULL DEFAULT 'General',
      status TEXT NOT NULL CHECK(status IN ('P','A','L')),
      UNIQUE(roll, day, subject)
    );
    """)
    row = con.execute("SELECT value FROM settings WHERE key='faculty_password'").fetchone()
    if not row:
        con.execute("INSERT INTO settings(key,value) VALUES('faculty_password',?)",
                    (generate_password_hash("faculty123"),))
    con.commit(); con.close()

def faculty_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("faculty"):
            return jsonify(error="Faculty login required"), 401
        return f(*a, **kw)
    return wrapper

@app.route("/")
def home():
    return render_template("index.html")

@app.post("/api/login/faculty")
def faculty_login():
    data = request.json or {}
    con = db()
    row = con.execute("SELECT value FROM settings WHERE key='faculty_password'").fetchone()
    con.close()
    if not row or not check_password_hash(row["value"], data.get("password","")):
        return jsonify(error="Incorrect faculty password"), 401
    session["faculty"] = True
    return jsonify(ok=True)

@app.post("/api/login/student")
def student_login():
    roll = (request.json or {}).get("roll","").strip()
    con = db()
    s = con.execute("SELECT * FROM students WHERE lower(roll)=lower(?)",(roll,)).fetchone()
    con.close()
    if not s:
        return jsonify(error="Roll number not found"), 404
    session["student_roll"] = s["roll"]
    return jsonify(ok=True, roll=s["roll"])

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/students")
@faculty_required
def students():
    con=db(); rows=con.execute("SELECT * FROM students ORDER BY roll").fetchall(); con.close()
    return jsonify(students=[dict(x) for x in rows])

@app.post("/api/students")
@faculty_required
def add_student():
    d=request.json or {}
    required = ("roll","name")
    if not all(str(d.get(k,"")).strip() for k in required):
        return jsonify(error="Roll and name are required"),400
    con=db()
    try:
        con.execute("""INSERT INTO students(roll,name,branch,semester,phone,email,subject,notes)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    tuple(d.get(k,"").strip() for k in
                          ("roll","name","branch","semester","phone","email","subject","notes")))
        con.commit()
    except sqlite3.IntegrityError:
        con.close(); return jsonify(error="Roll number already exists"),409
    con.close(); return jsonify(ok=True)

@app.put("/api/students/<roll>")
@faculty_required
def edit_student(roll):
    d=request.json or {}; con=db()
    con.execute("""UPDATE students SET name=?,branch=?,semester=?,phone=?,email=?,subject=?,notes=?
                   WHERE roll=?""",
                tuple(d.get(k,"").strip() for k in
                      ("name","branch","semester","phone","email","subject","notes"))+(roll,))
    con.commit(); con.close(); return jsonify(ok=True)

@app.delete("/api/students/<roll>")
@faculty_required
def delete_student(roll):
    con=db(); con.execute("DELETE FROM attendance WHERE roll=?",(roll,)); con.execute("DELETE FROM students WHERE roll=?",(roll,)); con.commit(); con.close()
    return jsonify(ok=True)

@app.get("/api/attendance")
@faculty_required
def get_attendance():
    day=request.args.get("day",str(date.today()))
    con=db()
    rows=con.execute("""SELECT s.roll,s.name,s.subject,a.status FROM students s
                        LEFT JOIN attendance a ON a.roll=s.roll AND a.day=? AND a.subject=COALESCE(s.subject,'General')
                        ORDER BY s.roll""",(day,)).fetchall()
    con.close(); return jsonify(day=day, records=[dict(x) for x in rows])

@app.post("/api/attendance")
@faculty_required
def mark_attendance():
    d=request.json or {}; roll=d.get("roll","").strip(); day=d.get("day",str(date.today()))
    status=d.get("status"); subject=d.get("subject") or "General"
    if status not in ("P","A","L"): return jsonify(error="Invalid status"),400
    con=db()
    con.execute("""INSERT INTO attendance(roll,day,subject,status) VALUES(?,?,?,?)
                   ON CONFLICT(roll,day,subject) DO UPDATE SET status=excluded.status""",
                (roll,day,subject,status))
    con.commit(); con.close(); return jsonify(ok=True)

@app.post("/api/change-password")
@faculty_required
def change_password():
    d=request.json or {}; old=d.get("old",""); new=d.get("new","")
    con=db(); row=con.execute("SELECT value FROM settings WHERE key='faculty_password'").fetchone()
    if not row or not check_password_hash(row["value"],old):
        con.close(); return jsonify(error="Current password is incorrect"),400
    if len(new)<6: con.close(); return jsonify(error="New password must be at least 6 characters"),400
    con.execute("UPDATE settings SET value=? WHERE key='faculty_password'",(generate_password_hash(new),))
    con.commit(); con.close(); return jsonify(ok=True)

@app.get("/api/me/student")
def student_me():
    roll=session.get("student_roll")
    if not roll: return jsonify(error="Student login required"),401
    con=db()
    s=con.execute("SELECT * FROM students WHERE roll=?",(roll,)).fetchone()
    rows=con.execute("""SELECT day,subject,status FROM attendance WHERE roll=? ORDER BY day DESC""",(roll,)).fetchall()
    con.close()
    if not s: return jsonify(error="Student not found"),404
    records=[dict(x) for x in rows]
    total=len(records); present=sum(x["status"]=="P" for x in records); late=sum(x["status"]=="L" for x in records)
    pct=round((present + late*.5)/total*100) if total else 0
    return jsonify(student=dict(s),records=records,percentage=pct)

if __name__=="__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
else:
    init_db()
