from flask import Flask, request, render_template, jsonify
from symcrypto import symcrypt_encrypt

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    message = data["message"]
    result = symcrypt_encrypt(message)
    return jsonify({"emoji_grid": result["symbolic_output"]})

if __name__ == "__main__":
    app.run(debug=True)