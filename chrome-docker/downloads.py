from flask import Flask, send_from_directory, render_template_string
import os

app = Flask(__name__)

DOWNLOADS_PATH = '/home/user/Downloads'

@app.route('/')
def list_files():
    files = os.listdir(DOWNLOADS_PATH)
    return render_template_string('''
        <head>
            <meta http-equiv="refresh" content="5">
        </head>
        <body style="background-color: #323437">
            <h1 style="color: white">Download Files</h1>
            <ul> 
                {% for file in files %}
                    {% if "-malicious" in file %}
                                  
                        <li><a href="{{ url_for('download_file', filename=file) }}" style="color:red">{{ file }}</a></li>
                    {% else %}
                        <li><a href="{{ url_for('download_file', filename=file) }}" style="color:white">{{ file }}</a></li>
                    {% endif %}
                {% endfor %}
            </ul>       
        </body>                       
    ''', files=files)

@app.route("/downloads/<filename>")
def download_file(filename):
    return send_from_directory(DOWNLOADS_PATH, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=9000)