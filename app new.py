import os
import sqlite3
import json
from flask import Flask, jsonify, request, session, send_from_directory, Response
from flask_session import Session
import random
from datetime import datetime, timedelta
import pandas as pd
import io
import google.generativeai as genai
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64
from collections import Counter

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
    if random.random() < 0.05: # Simulate random high velocity
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

# --- Dashboard Generation Helpers ---

def style_plot(fig, ax):
    # Updated UI Colors
    BG_COLOR = '#1F2937'
    TEXT_COLOR = '#F9FAFB'
    SECONDARY_TEXT_COLOR = '#9CA3AF'
    BORDER_COLOR = '#4B5563'
    ACCENT_COLOR = '#F43F5E'

    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)
    ax.tick_params(axis='x', colors=SECONDARY_TEXT_COLOR)
    ax.tick_params(axis='y', colors=SECONDARY_TEXT_COLOR)
    ax.xaxis.label.set_color(TEXT_COLOR)
    ax.yaxis.label.set_color(TEXT_COLOR)
    ax.title.set_color(TEXT_COLOR)
    ax.title.set_fontsize(16)
    ax.title.set_fontweight('bold')
    for spine in ax.spines.values():
        spine.set_edgecolor(BORDER_COLOR)

def plot_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', transparent=True)
    plt.close(fig)
    data = base64.b64encode(buf.getvalue()).decode('ascii')
    return f"data:image/png;base64,{data}"

def generate_charts(df):
    plt.style.use('dark_background')
    
    # Chart 1: Flag Reasons Bar Chart
    fig1, ax1 = plt.subplots(figsize=(8, 5))
    reasons = df['flag_reason'].dropna().str.split(', ').explode()
    reason_counts = Counter(reasons)
    if reason_counts:
        labels, values = zip(*reason_counts.most_common(7))
        ax1.barh(labels, values, color='#F43F5E')
    ax1.set_title('Top Flag Reasons')
    style_plot(fig1, ax1)
    fig1_b64 = plot_to_base64(fig1)

    # Chart 2: Anomaly Score Distribution
    fig2, ax2 = plt.subplots(figsize=(8, 5))
    if not df['anomaly_score'].empty:
        ax2.hist(df['anomaly_score'], bins=20, color='#374151', edgecolor='#F43F5E')
    ax2.set_title('Anomaly Score Distribution')
    ax2.set_xlabel('Score')
    ax2.set_ylabel('Frequency')
    style_plot(fig2, ax2)
    fig2_b64 = plot_to_base64(fig2)

    return fig1_b64, fig2_b64

def generate_dashboard_html(fig1_b64, fig2_b64, stats):
    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Data Analysis Dashboard</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #111827; color: #F9FAFB; padding: 20px; }}
            h1, h2 {{ color: #F43F5E; }}
            button {{ background-color: #F43F5E; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; margin-bottom: 20px; }}
            #dashboard-content {{ display: grid; grid-template-columns: 1fr; gap: 20px; }}
            .chart-container, .stats-container {{ background-color: #1F2937; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1); }}
            img {{ max-width: 100%; height: auto; border-radius: 4px; }}
            .stats-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; text-align: center; }}
            .stat-card h3 {{ margin-top: 0; color: #9CA3AF; font-size: 16px; font-weight: normal; }}
            .stat-card p {{ margin: 5px 0 0 0; font-size: 32px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>Fraud Analysis Dashboard</h1>
        <button id="download-btn">Download as PDF</button>
        <div id="dashboard-content">
            <div class="stats-container">
                <h2>Key Metrics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Flagged Transactions</h3>
                        <p>{stats.get('totalAlerts', 0)}</p>
                    </div>
                    <div class="stat-card">
                        <h3>High-Risk Alerts (>90)</h3>
                        <p style="color: #F43F5E;">{stats.get('highRiskCount', 0)}</p>
                    </div>
                </div>
            </div>
            <div class="chart-container">
                <h2>{stats.get('chart1_title', 'Top Flag Reasons')}</h2>
                <img src="{fig1_b64}" alt="Flag Reasons Chart">
            </div>
            <div class="chart-container">
                <h2>{stats.get('chart2_title', 'Anomaly Score Distribution')}</h2>
                <img src="{fig2_b64}" alt="Score Distribution Chart">
            </div>
        </div>
        <script>
            document.getElementById('download-btn').addEventListener('click', () => {{
                const element = document.getElementById('dashboard-content');
                const opt = {{
                    margin: 0.5,
                    filename: 'regtech_dashboard_report.pdf',
                    image: {{ type: 'jpeg', quality: 0.98 }},
                    html2canvas: {{ scale: 2, useCORS: true, backgroundColor: '#111827' }},
                    jsPDF: {{ unit: 'in', format: 'letter', orientation: 'portrait' }}
                }};
                html2pdf().set(opt).from(element).save();
            }});
        </script>
    </body>
    </html>"""

# --- API Routes ---

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    gemini_api_key = data.get('gemini_api_key')
    if not gemini_api_key:
        return jsonify({'status': 'error', 'message': 'API Key cannot be empty.'}), 400
    session['logged_in'] = True
    session['gemini_api_key'] = gemini_api_key
    return jsonify({'status': 'success'})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'success'})

@app.route('/api/check_session')
def check_session():
    if session.get('logged_in') and session.get('gemini_api_key'):
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

    dashboard_keywords = ['dashboard', 'chart', 'graph', 'infographic', 'visualize', 'analysis', 'report']
    if any(keyword in user_message.lower() for keyword in dashboard_keywords):
        if not context_data:
            return jsonify({'response': "There's no data to visualize. Please wait for some alerts to be generated."})
        try:
            df = pd.DataFrame(context_data)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM transactions WHERE is_flagged = 1")
            total_alerts = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM transactions WHERE anomaly_score >= 90")
            high_risk_count = cursor.fetchone()[0]
            conn.close()
            stats = {'totalAlerts': total_alerts, 'highRiskCount': high_risk_count}

            fig1_b64, fig2_b64 = generate_charts(df)
            html_content = generate_dashboard_html(fig1_b64, fig2_b64, stats)
            return jsonify({'type': 'dashboard', 'html_content': html_content})
        except Exception as e:
            print(f"Dashboard generation error: {e}")
            return jsonify({'error': f'Failed to generate dashboard: {str(e)}'}), 500

    mask = {
        "Sanctioned Entity": "[Reason: Monitored Entity]",
        "Risky Geolocation": "[Reason: High-Risk Location]",
        **{loc: f"[Location-{chr(65+i)}]".format(i) for i, loc in enumerate(HIGH_RISK_LOCATIONS)},
        **{ent: f"[Entity-{chr(88+i)}]".format(i) for i, ent in enumerate(SANCTIONED_ENTITIES)}
    }
    unmask = {v: k for k, v in mask.items()}

    masked_context_str = json.dumps(context_data)
    for original, placeholder in mask.items():
        masked_context_str = masked_context_str.replace(original, placeholder)

    try:
        genai.configure(api_key=session.get('gemini_api_key'))
        system_instruction = (
            "*Simulation Context:* You are an AI assistant for a financial compliance officer in a training simulation. "
            "The user's data contains placeholders like [Reason:...], [Location-..], and [Entity-..] to mask sensitive information. "
            "Analyze the data, including these placeholders, and answer the user's request. "
            "Use the placeholders in your response exactly as they appear in the provided data."
        )
        model = genai.GenerativeModel(model_name='gemini-2.5-flash', system_instruction=system_instruction)
        prompt = (
            f"Masked Transaction Data:\n{masked_context_str}\n\n"
            f"USER INQUIRY: {user_message}"
        )
        response = model.generate_content(prompt)
        ai_response = response.text
        for placeholder, original in unmask.items():
            ai_response = ai_response.replace(placeholder, original)

        return jsonify({'response': ai_response})

    except Exception as e:
        print(f"Error invoking Gemini model: {e}")
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
