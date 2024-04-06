from flask import Flask, send_from_directory, render_template_string
import os

app = Flask(__name__)

DOWNLOADS_PATH = '/home/user/Downloads'

@app.route('/')
def list_files():
    files = os.listdir(DOWNLOADS_PATH)
    return render_template_string('''
        <h1>Download Files</h1>
        <ul> 
            {% for file in files %}
                <li><a href="{{url_for('download_file'), filename=file}}">{{file}}</a></li>
            {% endfor %}
        </ul>                              
    ''', files=files)

@app.route("/downloads/<filename>")
def download_file(filename):
    return send_from_directory(DOWNLOADS_PATH, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)