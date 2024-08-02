from flask import Flask, request, jsonify
import subprocess
import os
import yaraengine

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

engine = yaraengine.engine()

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def run_sandbox(file_path):
    file_path = os.path.abspath(file_path)
    #print(file_path)
    docker_image = "sandbox"
    command = ["docker", "run", "--rm", "-v", f"{file_path}:/app/executable", docker_image, "/app/executable"]
    # docker run --rm -v C:\Users\Ben\OneDrive\מסמכים\GitHub\browser-sandbox\file-check-server\sandbox-docker\a.out:/app/a.out sandbox /app/a.out

    try:
        result = subprocess.check_output(command)
        #output = result.stdout
    except Exception as e:
        print("error")
        #output = e.stdout

    #print(result)
    return result.decode()

def file_checks(filepath):
    result = {
        "is_valid": True,
        "message": "File is okay.",
    }

    if engine.CheckFile(filepath):
        print("test static")
        result["is_valid"] = False
        result["message"] = "File is a virus"
    if "malicious" in run_sandbox(filepath):
        print("test dynamic")
        result["is_valid"] = False
        result["message"] = "File is a virus"



    #print(result["is_valid"])
    return result

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

            result = file_checks(filepath)
            
            os.remove(filepath)

            return jsonify(result)

        return jsonify({"error": "File not allowed"}), 400
    except Exception as e:
        return jsonify({"error": "File too large"}), 413

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
