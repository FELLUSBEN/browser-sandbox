from flask import Flask, render_template, redirect, url_for
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_sandbox', methods=['POST'])
def create_sandbox():
    
    subprocess.run(['docker', 'run', '-d', 'nginx'])
    return redirect(url_for('sandbox'))

@app.route('/sandbox')
def sandbox():
    return 'Docker container created!'

if __name__ == '__main__':
    app.run(debug=True)
