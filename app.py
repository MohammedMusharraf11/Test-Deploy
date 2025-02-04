from flask import Flask, render_template, make_response, request
import base64

app = Flask(__name__)

# Encrypt the flag using Base64
FLAG = "kalpana_2025{super_secret_cookie}"
ENCRYPTED_FLAG = base64.b64encode(FLAG.encode()).decode()

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == 'PESU-EC-Campus' and password == 'PESU-EC-Campus':
        # Set fake cookies to mislead players
        resp = make_response(render_template('dashboard.html'))
        resp.set_cookie('fake_cookie_1', 'this_is_not_the_flag')
        resp.set_cookie('fake_cookie_2', 'still_not_the_flag')
        resp.set_cookie('fake_cookie_3', 'keep_looking')
        
        # Set a custom header with part of the flag
        resp.headers['X-Flag-Part'] = 'kalpana_2025{super_'
        
        return resp
    else:
        return "Invalid credentials!"

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/hidden')
def hidden():
    # This route sets the encrypted cookie via JavaScript
    resp = make_response(render_template('hidden.html'))
    resp.set_cookie('admin_secret', ENCRYPTED_FLAG, httponly=True)
    return resp

if __name__ == '__main__':
    app.run(debug=True)
