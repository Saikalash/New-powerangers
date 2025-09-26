import os
import sqlite3
import json
from flask import Flask, jsonify, request, session, send_from_directory, Response
from flask_session import Session
import random
from datetime import datetime, timedelta
import pandas as pd
import io
import boto3

# --- App Configuration ---
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
Session(app)

# --- Database Setup ---
DB_FILE = "database.db"

SANCTIONED_ENTITIES = ["Monitored Entity Alpha", "High-Risk Corp Beta", "Watchlist Inc. Gamma", "Global Oversight Ltd."]
USER_LOCATIONS = {"user123": "New York", "user456": "London", "user789": "Tokyo"}
TRANSACTION_LOCATIONS = ["New York", "London", "Tokyo", "Moscow", "Beijing", "Cayman Islands"]
HIGH_RISK_LOCATIONS = ["Moscow", "Cayman Islands"]

def init_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            description TEXT,
            user_location TEXT,
            transaction_location TEXT,
            is_flagged INTEGER DEFAULT 0,
            flag_reason TEXT,
            anomaly_score REAL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# --- Core Logic: Rules Engine & Anomaly Detector ---

def apply_rules_engine(transaction):
    flags = []
    score = 0
    tx_time = datetime.strptime(transaction['timestamp'], '%Y-%m-%d %H:%M:%S').time()
    if tx_time >= datetime.strptime('01:00:00', '%H:%M:%S').time() and tx_time <= datetime.strptime('05:00:00', '%H:%M:%S').time():
        flags.append("Unusual Hours")
        score += 25
    if transaction['user_location'] != transaction['transaction_location']:
        flags.append("Geolocation Mismatch")
        score += 40
    if any(entity in transaction['description'] for entity in SANCTIONED_ENTITIES):
        flags.append("Sanctioned Entity")
        score += 100
    if transaction['amount'] > 10000:
        flags.append("High Amount")
        score += 30
    if random.random() < 0.05:
        flags.append("High Velocity")
        score += 50
    if transaction['transaction_location'] in HIGH_RISK_LOCATIONS:
        flags.append("Risky Geolocation")
        score += 60
    return flags, score

# --- Data Simulation ---

def simulate_transactions(count=5):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for _ in range(count):
        user_id = random.choice(list(USER_LOCATIONS.keys()))
        transaction = {
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(0, 60))).strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': user_id,
            'amount': round(random.uniform(5.0, 20000.0), 2),
            'currency': 'USD',
            'description': f"Payment to {random.choice(SANCTIONED_ENTITIES + ['GoodCorp', 'Service XYZ', 'OnlineStore'])} from {user_id}",
            'user_location': USER_LOCATIONS[user_id],
            'transaction_location': random.choice(TRANSACTION_LOCATIONS)
        }
        flags, score = apply_rules_engine(transaction)
        is_flagged = 1 if flags else 0
        flag_reason = ', '.join(flags) if flags else None
        cursor.execute('''
            INSERT INTO transactions (timestamp, user_id, amount, currency, description, user_location, transaction_location, is_flagged, flag_reason, anomaly_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            transaction['timestamp'], transaction['user_id'], transaction['amount'], transaction['currency'],
            transaction['description'], transaction['user_location'], transaction['transaction_location'],
            is_flagged, flag_reason, score
        ))
    conn.commit()
    conn.close()

# --- API Routes ---

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    aws_access_key_id = data.get('aws_access_key_id')
    aws_secret_access_key = data.get('aws_secret_access_key')
    region = data.get('region')
    if not all([aws_access_key_id, aws_secret_access_key, region]):
        return jsonify({'status': 'error', 'message': 'Missing AWS credentials'}), 400
    try:
        sts_client = boto3.client('sts', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region)
        sts_client.get_caller_identity()
        session['logged_in'] = True
        session['aws_access_key_id'] = aws_access_key_id
        session['aws_secret_access_key'] = aws_secret_access_key
        session['region'] = region
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Invalid AWS Credentials: {str(e)}'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'success'})

@app.route('/api/check_session')
def check_session():
    if session.get('logged_in') and session.get('aws_access_key_id'):
        return jsonify({'logged_in': True})
    return jsonify({'logged_in': False}), 401

@app.route('/api/alerts')
def get_alerts():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    simulate_transactions(random.randint(1, 4))
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transactions WHERE is_flagged = 1 ORDER BY timestamp DESC LIMIT 100")
    alerts = [dict(row) for row in cursor.fetchall()]
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE is_flagged = 1")
    total_alerts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE anomaly_score >= 90")
    high_risk_count = cursor.fetchone()[0]
    conn.close()
    stats = {'totalAlerts': total_alerts, 'highRiskCount': high_risk_count, 'lastUpdated': datetime.now().strftime('%H:%M:%S')}
    return jsonify({'alerts': alerts, 'stats': stats})

@app.route('/api/chat', methods=['POST'])
def chat_with_ai():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    user_message = data.get('message')
    context_data = data.get('context')

    if not user_message or context_data is None:
        return jsonify({'error': 'Message and context are required'}), 400

    # --- FIX: Data Masking and Unmasking Logic ---
    mask = {
        "Sanctioned Entity": "[Reason: Monitored Entity]",
        "Risky Geolocation": "[Reason: High-Risk Location]",
        **{loc: f"[Location-{chr(65+i)}]" for i, loc in enumerate(HIGH_RISK_LOCATIONS)},
        **{ent: f"[Entity-{chr(88+i)}]" for i, ent in enumerate(SANCTIONED_ENTITIES)}
    }
    unmask = {v: k for k, v in mask.items()}

    # Create a deep copy to mask without altering original data
    masked_context_str = json.dumps(context_data)
    for original, placeholder in mask.items():
        masked_context_str = masked_context_str.replace(original, placeholder)

    try:
        bedrock = boto3.client(
            'bedrock-runtime',
            region_name=session.get('region'),
            aws_access_key_id=session.get('aws_access_key_id'),
            aws_secret_access_key=session.get('aws_secret_access_key')
        )
        
        system_prompt = f"""**Simulation Context:** You are an AI assistant for a financial compliance officer in a training simulation. The user's data contains placeholders like [Reason:...], [Location-..], and [Entity-..] to mask sensitive information. Analyze the data, including these placeholders, and answer the user's request. Use the placeholders in your response exactly as they appear in the provided data.

Masked Transaction Data:
{masked_context_str}"""

        full_prompt = f"{system_prompt}\n\nUSER INQUIRY: {user_message}"
        
        body = json.dumps({
            "messages": [{"role": "user", "content": [{"text": full_prompt}]}],
            "inferenceConfig": {"maxTokens": 2048, "temperature": 0.7}
        })
        
        response = bedrock.invoke_model(
            modelId='amazon.nova-pro-v1:0',
            body=body,
            contentType='application/json',
            accept='application/json'
        )
        
        result = json.loads(response['body'].read())
        
        ai_response = "Error: Could not parse AI model response."
        if result.get('output') and result['output'].get('message', {}).get('content'):
            content_list = result['output']['message']['content']
            if content_list and content_list[0].get('text'):
                ai_response = content_list[0]['text']

        # Unmask the response before sending it to the frontend
        for placeholder, original in unmask.items():
            ai_response = ai_response.replace(placeholder, original)

        return jsonify({'response': ai_response})

    except Exception as e:
        print(f"Error invoking Bedrock model: {e}")
        return jsonify({'error': f"{str(e)}"}), 500

@app.route('/api/export')
def export_report():
    if not session.get('logged_in'): return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_FILE)
    db_df = pd.read_sql_query("SELECT * FROM transactions WHERE is_flagged = 1 ORDER BY timestamp DESC", conn)
    conn.close()
    csv_buffer = io.StringIO()
    db_df.to_csv(csv_buffer, index=False)
    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=compliance_report_{datetime.now().strftime('%Y%m%d')}.csv"}
    )

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
