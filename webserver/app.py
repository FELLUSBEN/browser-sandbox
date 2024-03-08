from flask import Flask, render_template, redirect, url_for, session
import subprocess
import uuid

port_1 = 5900
port_2 = 6080
port_map = {}

app = Flask(__name__)
app.secret_key = "tmp"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_sandbox', methods=['POST'])
def create_sandbox():
    global port_1, port_2    
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    
    if session['user_id'] in port_map:
        id = session['user_id']
        return redirect(f'sandbox/{id}')

    print(session['user_id'])
    port_map[session['user_id']] = port_2
    subprocess.Popen(['docker','run','--name',f'{session["user_id"]}','-p', f'{str(port_1)}:5900', '-p', f'{str(port_2)}:6080','ubuntu-vnc-chrome'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL ) # create a new docker container
    port_1, port_2 = port_1 + 1, port_2 + 1
    return redirect(url_for('sandbox'))

@app.route('/sandbox/<id>')
def sandbox_vm(id):
    vm_port = port_map[session['user_id']]
    return render_template('vm.html', num=vm_port)

@app.route('/sandbox')
def sandbox():
    id = session['user_id']
    return redirect(f'sandbox/{id}')

if __name__ == '__main__':
    app.run(debug=True)
