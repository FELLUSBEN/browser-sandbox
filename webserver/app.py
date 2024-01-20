from flask import Flask, render_template, redirect, url_for, session
import subprocess
import uuid

app = Flask(__name__)
app.secret_key = "tmp"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_sandbox', methods=['POST'])
def create_sandbox():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    print(session['user_id'])
    subprocess.Popen(['docker','run','--name',f'{session["user_id"]}','-p', '5900:5900', '-p', '6080:6080','ubuntu-vnc-chrome'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL ) # create a new docker container
    return redirect(url_for('sandbox'))



@app.route('/sandbox')
def sandbox():
    return 'Docker container created!'

if __name__ == '__main__':
    app.run(debug=True)
