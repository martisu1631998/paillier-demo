from flask import Flask, request, jsonify
from paillier.paillier import Paillier  # Import your Paillier class
import json

app = Flask(__name__)

# Initialize the Paillier instance
paillier_instance = Paillier()

@app.route('/encrypt', methods=['POST'])
def encrypt_scores():
    data = request.json
    scores = data.get('scores', [])
    encrypted_scores = [paillier_instance.encrypt(int(score)) for score in scores]
    return jsonify({"encrypted_scores": encrypted_scores})

@app.route('/crunch', methods=['POST'])
def crunch():
    data = request.json
    encrypted_scores = data.get('encrypted_scores', [])
    # Simulate homomorphic addition/multiplication (replace this with real operations)
    result = sum(encrypted_scores)  # Replace with homomorphic operations
    return jsonify({"crunched_result": result})

@app.route('/decrypt', methods=['POST'])
def decrypt_result():
    data = request.json
    encrypted_result = data.get('encrypted_result', 0)
    decrypted_result = paillier_instance.decrypt(encrypted_result)
    return jsonify({"decrypted_result": decrypted_result})

if __name__ == '__main__':
    app.run(debug=True)
