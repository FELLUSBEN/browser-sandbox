from flask import Flask, render_template, redirect, url_for, session, request, Response, stream_with_context
import requests
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

@app.route('/loading')
def loading():
    return render_template('loading.html')

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
    subprocess.Popen(['docker','run','--name',f'{session["user_id"]}','-p', f'{str(port_1)}:5900', '-p', f'{str(port_2)}:6080','test'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL ) # create a new docker container
    port_1, port_2 = port_1 + 1, port_2 + 1
    return redirect(url_for('loading'))

@app.route('/sandbox/<id>/')
def sandbox_vm(id):
    if 'user_id' not in session:
        return redirect('/')
    if session['user_id'] not in port_map:
        return redirect('/')
    vm_port = port_map[session['user_id']]
    #req_stream = requests.get(f"http://127.0.0.1:{vm_port}/{path}/", stream=True, params=request.args)
    #excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    #headers = [(name, value) for (name, value) in req_stream.raw.headers.items() if name.lower() not in excluded_headers]

    #return Response(stream_with_context(req_stream.iter_content(chunk_size=1024)), content_type=req_stream.headers['Content-Type'])
    
    return render_template('vm.html', num=vm_port)


@app.route('/sandbox')
def sandbox():
    if 'user_id' not in session:
        return redirect('/')
    if session['user_id'] not in port_map:
        return redirect('/')
    id = session['user_id']
    return redirect(f'sandbox/{id}/')

if __name__ == '__main__':
    app.run(debug=True, threaded=True)

