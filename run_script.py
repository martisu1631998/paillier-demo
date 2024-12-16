from flask import Flask, request, jsonify, render_template
import random
import math
import sympy

from script import paillier_instance, crunch

app = Flask(__name__)

# Flask routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    try:
        # Generate key pair
        instance = paillier_instance()
        pub_key = instance.get_pub_key()
        priv_key = instance.priv_key
        return jsonify({"pub_key": pub_key, "priv_key": priv_key})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/encrypt", methods=["POST"])
def encrypt():
    try:
        data = request.json
        scores = data.get("scores")
        pub_key = data.get("pub_key")
        instance = paillier_instance()
        instance.n, instance.g = pub_key  # Use the provided public key
        encrypted_scores = instance.encrypt(scores)
        return jsonify({"encrypted_scores": encrypted_scores})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/compute", methods=["POST"])
def compute():
    try:
        data = request.json
        encrypted_scores = data.get("encrypted_scores")
        pub_key = data.get("pub_key")
        result = crunch(encrypted_scores, pub_key)
        return jsonify({"encrypted_result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt():
    try:
        data = request.json
        encrypted_result = data.get("encrypted_result")
        priv_key = data.get("priv_key")
        instance = paillier_instance()
        instance.lambd, instance.mu = priv_key  # Use the provided private key
        decrypted_result = instance.decrypt(encrypted_result)
        return jsonify({"decrypted_result": decrypted_result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
