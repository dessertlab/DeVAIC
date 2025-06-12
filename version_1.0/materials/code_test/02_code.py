from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/profile")
def profile():
    username = request.args.get('username')
    response = make_response(f"Hello {username}")
    return response
