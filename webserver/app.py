from flask import Flask, render_template, redirect, url_for, session, request, Response, stream_with_context
import requests
import subprocess
import uuid
import threading

port_1 = 5900
port_2 = 6080
port_3 = 9000
port_map = {}

app = Flask(__name__)

app.secret_key = "tmp"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/loading_exit')
def loading_exit():
    return render_template('loading_exit.html')

@app.route('/download', methods=['POST'])
def download():
    pass

@app.route("/end_session", methods=['POST'])
def end_session():
    threading.Thread(target=delete_vm, args=(session['user_id'],), daemon=True).start()
    session.clear()
    return redirect("/loading_exit")

@app.route('/create_sandbox', methods=['POST'])
def create_sandbox():
    global port_1, port_2, port_3  
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    
    if session['user_id'] in port_map:
        id = session['user_id']
        return redirect(f'sandbox/{id}')

    width = request.form.get("width")
    height = request.form.get("height")


    print(session['user_id'])
    port_map[session['user_id']] = (port_2,port_3)
    subprocess.Popen(['docker','run','--name',f'{session["user_id"]}','-p', f'{str(port_1)}:5900', '-p', f'{str(port_2)}:6080', '-p', f'{str(port_3)}:9000', '-e', f'SCREEN_WIDTH={width}', '-e', f'SCREEN_HEIGHT={height}','test3'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL ) # create a new docker container
    port_1, port_2, port_3 = port_1 + 1, port_2 + 1, port_3 + 1
    return redirect(url_for('loading'))

@app.route('/sandbox/<id>/')
def sandbox_vm(id):
    if 'user_id' not in session:
        return redirect('/')
    if session['user_id'] not in port_map:
        return redirect('/')
    ip_address = request.host.split(":")[0]
    vm_port = port_map[session['user_id']][0]
    download_port = port_map[session['user_id']][1]
    return render_template('vm.html', num=vm_port, download_port=download_port, ip=ip_address )


@app.route('/sandbox')
def sandbox():
    if 'user_id' not in session:
        return redirect('/')
    if session['user_id'] not in port_map:
        return redirect('/')
    id = session['user_id']
    return redirect(f'sandbox/{id}/')

def delete_vm(name):
    subprocess.run(['docker','stop',name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL )
    subprocess.run(['docker','rm',name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL )


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, threaded=True)

