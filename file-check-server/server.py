from flask import Flask, request, jsonify
import os
import yaraengine

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

engine = yaraengine.engine()

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def file_checks(filepath):
    result = {
        "is_valid": True,
        "message": "File is okay.",
    }

    if engine.CheckFile(filepath):
        result["is_valid"] = False
        result["message"] = "File is a virus"

    print(result["is_valid"])
    return result

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        result = file_checks(filepath)
        
        os.remove(filepath)

        return jsonify(result)

    return jsonify({"error": "File not allowed"}), 400

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
