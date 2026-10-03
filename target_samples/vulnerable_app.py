"""
Sample Vulnerable Application for SecurityTest-AI SAST and DAST evaluation.
WARNING: Contains intentional security flaws for automated testing & demonstration.
"""

import os
import pickle
import hashlib
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# SECURITY ISSUE 1: Hardcoded Secrets
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_EXPOSED_IN_SOURCE"
JWT_SECRET = "super_insecure_default_secret_12345"
DATABASE_PASSWORD = "admin_root_password_2026!"

# SECURITY ISSUE 2: Weak Hashing Algorithm (MD5)
def hash_user_password(password: str) -> str:
    """Uses deprecated MD5 algorithm without salt."""
    return hashlib.md5(password.encode()).hexdigest()

# SECURITY ISSUE 3: SQL Injection via Raw String Concatenation
@app.route('/api/user', methods=['GET'])
def get_user_profile():
    username = request.args.get('username', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Flaw: String formatting introduces SQL Injection (CWE-89)
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return jsonify({"user": user})

# SECURITY ISSUE 4: Command Injection via shell=True / os.system
@app.route('/api/ping', methods=['POST'])
def ping_host():
    data = request.get_json() or {}
    host = data.get('host', '127.0.0.1')
    # Flaw: User supplied input directly passed to shell (CWE-78)
    cmd = f"ping -c 1 {host}"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return jsonify({"output": output})

# SECURITY ISSUE 5: Insecure Deserialization (Pickle)
@app.route('/api/session/load', methods=['POST'])
def load_session():
    data = request.data
    # Flaw: Arbitrary code execution via pickle.loads (CWE-502)
    session_obj = pickle.loads(data)
    return jsonify({"status": "loaded", "data": str(session_obj)})

# SECURITY ISSUE 6: Path Traversal
@app.route('/api/files/read', methods=['GET'])
def read_log_file():
    filename = request.args.get('file', '')
    # Flaw: Direct path concatenation allows directory traversal (CWE-22)
    filepath = os.path.join('/var/log/app', filename)
    with open(filepath, 'r') as f:
        content = f.read()
    return jsonify({"content": content})

if __name__ == '__main__':
    # Flaw: debug=True exposed in production, host 0.0.0.0
    app.run(host='0.0.0.0', port=5000, debug=True)
