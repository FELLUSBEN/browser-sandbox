from flask import Flask, request, jsonify
import subprocess
import os
import queue
import yaraengine
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import sqlite3
from threading import Lock

app = Flask(__name__)

DATABASE_FILE = "file_hashes.db"
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

executer = ThreadPoolExecutor()

user_locks = {}

sqlite3.register_converter("BOOLEAN", lambda v: v != '0')

engine = yaraengine.engine()

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                   hash TEXT PRIMARY KEY,
                   is_flaged BOOLEAN NOT NULL DEFAULT 0
                   )                   
                ''')
    conn.commit()
    conn.close()


def is_hash_in_db(file_hash):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT is_flaged FROM file_hashes WHERE hash = ?', (file_hash,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return bool(result[0])
    return None


def save_file_hash(filehash, is_flagged=False):
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO file_hashes (hash, is_flaged) VALUES (?, ?)', (filehash, is_flagged))
        conn.commit()
    except sqlite3.IntegrityError:
        print(f"Hash {filehash} already exists in database.")
    finally:
        conn.close()


def hashfile(filepath):
    hash_func = hashlib.new("sha256")
    
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def run_sandbox(file_path):
    file_path = os.path.abspath(file_path)
    #print(file_path)
    docker_image = "sandbox"
    audit_log_path = "/var/log/audit/audit.log"
    container_log_path = "/mnt/audit.log"
    command = ["docker", "run", "-d", "--rm", "-v", f"{file_path}:/app/executable", '-v', f'{audit_log_path}:{container_log_path}', docker_image, "/app/executable"]
    # docker run --rm -v C:\Users\Ben\OneDrive\מסמכים\GitHub\browser-sandbox\file-check-server\sandbox-docker\a.out:/app/a.out sandbox /app/a.out
    try:
        result = subprocess.check_output(command)
        container_id, _ = result.communicate()
        container_id = container_id.decode('utf-8').strip()
        docker_pid = result.pid
        file_path_in_container = f"/mnt/pid.txt"
        create_file_command = [
            "docker", "exec", container_id, 
            "bash", "-c", f'echo "{docker_pid}" > {file_path_in_container}'
        ]
        subprocess.run(create_file_command, check=True)
    except Exception as e:
        print("error")
        #output = e.stdout

    #print(result)
    return result.decode()


def file_checks(filepath):
    print("test")
    result = {
        "is_valid": True,
        "message": "okay.",
    }
    if engine.CheckFile(filepath):
        result["is_valid"] = False
        result["message"] = "malicious"

    sandbox_output =  run_sandbox(filepath)

    if "malicious" in sandbox_output:
        result["is_valid"] = False
        if "informational" in sandbox_output:
            result["message"] = "malicious - informational level"
        elif "low" in sandbox_output:
            result["message"] = "malicious - low level"
        elif "medium" in sandbox_output:
            result["message"] = "malicious - medium level"
        elif "high" in sandbox_output:
            result["message"] = "malicious - high level"
        else:
            result["message"] = "malicious - critical level"

        print(result["message"])

    #print(result["is_valid"])
    return result

@app.before_request
def create_lock():
    user_id = request.remote_addr
    if user_id not in user_locks:
        user_locks[user_id] = Lock()


@app.route('/upload', methods=['POST'])
def upload_file():
    try:

        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if file:
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print(os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], filename)))
            #filepath = os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file.save(filepath)

            filehash = hashfile(filepath)
            print(filehash)
            tmp = is_hash_in_db(filehash)
            if tmp != None:
                os.remove(filepath)
                if tmp == True:
                    print("Test")
                    return jsonify({"is_valid": False, "message": "virus"})
                else:
                    return jsonify({"is_valid": True, "message": "file is okay."})
            
            user_ip = request.remote_addr
            lock = user_locks.get(user_ip)
            with lock:
                future = executer.submit(file_checks, filepath)
                result = future.result()
                
                save_file_hash(filehash, not result["is_valid"])
                os.remove(filepath)

                return jsonify(result)

        return jsonify({"error": "File not allowed"}), 400
    except Exception as e:
        return jsonify({"error": "File too large"}), 413



if __name__ == '__main__':
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5001)
