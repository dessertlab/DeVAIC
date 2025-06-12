from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/')
def greet():
    name = request.args.get('name', '')
    response = make_response(f'<h1>Hello {name}</h1>')
    return response

if __name__ == '__main__':
    app.run(debug=True)