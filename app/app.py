from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return jsonify(
        message="Hello from the protected resource",
        client_ip=request.remote_addr,
        note="GET requires 'read' scope"
    )

@app.route("/write", methods=["POST"])
def write():
    data = request.get_json(silent=True) or {}
    return jsonify(status="wrote", data=data, note="POST requires 'write' scope")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
