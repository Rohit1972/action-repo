from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient
from datetime import datetime
import os
import hmac
import hashlib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# MongoDB Setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client.webhook_events

def compute_signature(payload_body):
    """Generate HMAC-SHA256 signature for verification."""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
    if not secret:
        return None  # Skip if no secret configured
    return hmac.new(secret, payload_body, hashlib.sha256).hexdigest()


@app.route('/get_token',methods=['POST'])
def getToken():
    print("Hii")
    return jsonify({'token':compute_signature(request.get_data())})


@app.route('/webhook', methods=['POST'])
def webhook():
    # Get raw request body (CRITICAL for correct hashing)
    payload_body = request.get_data()
    
    # Verify signature if secret exists
    expected_signature = compute_signature(payload_body)
    print(expected_signature)
    if expected_signature:
        received_signature = request.headers.get('X-Hub-Signature-256', '').split('sha256=')[-1]
        print(received_signature)
        if not hmac.compare_digest(expected_signature, received_signature):
            return jsonify({"error": "Invalid signature"}), 403
    
    # Process GitHub event
    try:
        data = request.json
    except:
        return jsonify({"error": "Invalid JSON"}), 400

    event_type = request.headers.get('X-GitHub-Event')
    
    if event_type == "push":
        event = {
            "request_id": data["head_commit"]["id"],
            "author": data["pusher"]["name"],
            "action": "PUSH",
            "from_branch": None,
            "to_branch": data["ref"].split('/')[-1],
            "timestamp": datetime.utcnow().isoformat()
        }
    elif event_type == "pull_request":
        pr = data["pull_request"]
        event = {
            "request_id": str(pr["number"]),
            "author": pr["user"]["login"],
            "action": "MERGE" if pr.get("merged") else "PULL_REQUEST",
            "from_branch": pr["head"]["ref"],
            "to_branch": pr["base"]["ref"],
            "timestamp": datetime.utcnow().isoformat()
        }
    else:
        return jsonify({"status": "ignored"}), 200
    
    # Store in MongoDB
    db.events.insert_one(event)
    return jsonify({"status": "success"}), 200

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/events')
def get_events():
    events = list(db.events.find().sort("timestamp", -1).limit(10))
    # Convert ObjectId to string for JSON
    for event in events:
        event["_id"] = str(event["_id"])
    return jsonify(events)

if __name__ == '__main__':
    app.run(debug=True)