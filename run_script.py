from flask import Flask, request, jsonify, render_template
import random
import math
import sympy

from script import paillier_instance, crunch

# Create a Flask app
app = Flask(__name__)

# Global instance of paillier_instance (keys generated once)
paillier = paillier_instance(verbose=True)

@app.route("/")
def index():
    """Render the HTML interface."""
    return render_template("index.html")

@app.route("/get_keys", methods=["GET"])
def get_keys():
    """Return the generated public and private keys."""
    return jsonify({
        "pub_key": paillier.get_pub_key(),
        "priv_key": paillier.priv_key
    })

@app.route("/encrypt", methods=["POST"])
def encrypt_scores():
    """Encrypt scores using the global Paillier instance."""
    try:
        data = request.json
        scores = data.get("scores")  # List of integers
        encrypted_scores = paillier.encrypt(scores, verbose=True)
        return jsonify({"encrypted_scores": encrypted_scores})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/compute", methods=["POST"])
def compute_encrypted_result():
    """Compute the encrypted result using the provided encrypted scores."""
    try:
        data = request.json
        encrypted_scores = data.get("encrypted_scores")  # List of integers
        pub_key = paillier.get_pub_key()
        encrypted_result = crunch(encrypted_scores, pub_key, verbose=True)
        return jsonify({"encrypted_result": encrypted_result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt_result():
    """Decrypt the final encrypted result to plaintext."""
    try:
        data = request.json
        encrypted_result = data.get("encrypted_result")  # Integer
        decrypted_result = paillier.decrypt(encrypted_result, verbose=True)
        return jsonify({"decrypted_result": decrypted_result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
