from flask import Flask, render_template_string, send_file
from flask_socketio import SocketIO, emit
import os
import time
import socket
import json
from threading import Thread
from io import BytesIO
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Directory setup ──
RUN_DIR = os.environ.get("HUNT_RUN_DIR", os.getcwd())
PROJECT_ROOT = os.path.abspath(os.path.join(RUN_DIR, "..", ".."))

logf = open(os.path.join(RUN_DIR, "dashboard.log"), "a")
logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Dashboard STARTED in run folder: {RUN_DIR}\n")
logf.flush()

# File paths
STATUS_PATH      = os.path.join(RUN_DIR, "status.json")
CONFIRMED_PATH   = os.path.join(RUN_DIR, "confirmed_redirects.txt")
LIKELY_PATH      = os.path.join(RUN_DIR, "likely_redirects.txt")
SUSPICIOUS_PATH  = os.path.join(RUN_DIR, "suspicious_redirects.txt")
LIVE_PATH        = os.path.join(RUN_DIR, "live.txt")
SUBS_PATH        = os.path.join(RUN_DIR, "subdomains.txt")

START_TIME = time.time()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

LOCAL_IP = get_local_ip()
PORT = 8787

def safe_readlines(path):
    full_path = os.path.abspath(path)
    if not os.path.exists(full_path):
        logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] MISSING FILE: {full_path}\n")
        logf.flush()
        return []
    try:
        with open(full_path, encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Read {len(lines)} lines from {os.path.basename(full_path)}\n")
        logf.flush()
        return lines
    except Exception as e:
        logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR reading {full_path}: {e}\n")
        logf.flush()
        return []

def get_urls():
    findings = []
    for u in safe_readlines(CONFIRMED_PATH):
        findings.append({"url": u, "classification": "CONFIRMED", "severity": 10})
    for u in safe_readlines(LIKELY_PATH):
        findings.append({"url": u, "classification": "LIKELY", "severity": 7})
    for u in safe_readlines(SUSPICIOUS_PATH):
        findings.append({"url": u, "classification": "SUSPICIOUS", "severity": 4})
    logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Loaded {len(findings)} findings\n")
    logf.flush()
    return findings

def get_subdomains():
    lines = safe_readlines(LIVE_PATH)
    if lines:
        return lines
    return safe_readlines(SUBS_PATH)

def get_status():
    default = {"phase": "Initializing", "progress": 0}
    if os.path.exists(STATUS_PATH):
        try:
            with open(STATUS_PATH) as f:
                data = json.load(f)
                default.update(data)
        except Exception as e:
            logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] status.json parse error: {e}\n")
    status = {
        "phase": default.get("phase", "IDLE"),
        "progress": int(default.get("progress", 0)),
        "total_domains": len(safe_readlines(os.path.join(PROJECT_ROOT, "domains.txt"))),
        "alive_domains": len(get_subdomains()),
        "redirectable": len(get_urls())
    }
    logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Status: {status}\n")
    logf.flush()
    return status

# ── Professional PDF Report ──
@app.route("/generate-report")
def generate_report():
    confirmed = safe_readlines(CONFIRMED_PATH)
    total_domains = len(safe_readlines(os.path.join(PROJECT_ROOT, "domains.txt")))
    runtime = str(datetime.timedelta(seconds=int(time.time() - START_TIME)))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=60,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Style for wrapped long URLs
    url_style = ParagraphStyle(
        name='URLStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=11,
        spaceAfter=4,
        alignment=0,
        wordWrap='CJK',
    )

    # Title style
    title_style = ParagraphStyle(
        name='TitleBold',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=18,
        textColor=colors.darkblue,
    )

    elements = []

    # Header
    elements.append(Paragraph("OPEN REDIRECT AUDIT REPORT", title_style))
    elements.append(Spacer(1, 0.2 * inch))

    # Metadata
    meta_data = [
        f"<b>Generated:</b> {now}",
        f"<b>Scope:</b> {total_domains} domains",
        f"<b>Runtime:</b> {runtime}",
    ]
    for line in meta_data:
        elements.append(Paragraph(line, styles['Normal']))
    elements.append(Spacer(1, 0.3 * inch))

    if not confirmed:
        elements.append(Paragraph(
            "No confirmed open redirects were identified during this scan.",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.4 * inch))
    else:
        elements.append(Paragraph(
            f"Confirmed Open Redirects Found: {len(confirmed)}",
            styles['Heading2']
        ))
        elements.append(Spacer(1, 12))

        # Table data with Paragraph for URLs
        data = [["#", "Endpoint URL"]]
        for i, url in enumerate(confirmed, 1):
            data.append([str(i), Paragraph(url, url_style)])

        table = Table(data, colWidths=[40, 440])

        table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0,0), (-1,0), colors.darkgrey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,0), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 11),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('TOPPADDING', (0,0), (-1,0), 10),

            # Body
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (0,1), (0,-1), 'CENTER'),
            ('ALIGN', (1,1), (1,-1), 'LEFT'),
            ('LEFTPADDING', (1,1), (1,-1), 8),
            ('RIGHTPADDING', (1,1), (1,-1), 8),
            ('FONTSIZE', (1,1), (1,-1), 9),
            ('LEADING', (1,1), (1,-1), 11),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    # Footer note
    elements.append(Paragraph(
        f"Report generated by HUNTER Adaptive Intelligence • {now}",
        ParagraphStyle(
            name='Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=1,
            spaceBefore=20
        )
    ))

    # Page number function
    def add_page_numbers(canvas, doc):
        page_num = canvas.getPageNumber()
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.grey)
        canvas.drawRightString(
            doc.rightMargin + doc.width,
            doc.bottomMargin - 20,
            f"Page {page_num}"
        )
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_page_numbers, onLaterPages=add_page_numbers)

    buffer.seek(0)

    filename = f"open-redirect-report_{datetime.datetime.now():%Y%m%d_%H%M%S}.pdf"

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )

HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HUNTER // Adaptive Intelligence</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono&family=Syncopate:wght@700&display=swap">
    <style>
        :root {
            --hue: 0;
            --sat: 90%;
            --bg-lightness: 6%;
            --text-lightness: 92%;
            --accent-lightness: 62%;
            --accent-sat: 90%;
            --border: rgba(255,255,255,0.09);
        }
        [data-theme="light"] {
            --bg-lightness: 96%;
            --text-lightness: 12%;
            --accent-lightness: 48%;
            --accent-sat: 75%;
            --border: rgba(0,0,0,0.09);
        }
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Inter', sans-serif;
            background: hsl(var(--hue), 18%, var(--bg-lightness));
            color: hsl(0, 0%, var(--text-lightness));
            min-height: 100vh;
            transition: background 0.8s ease, color 0.5s ease;
        }
        .app-container { padding: 24px 40px; max-width: 1640px; margin: 0 auto; }
        nav { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }
        .logo { font-family: 'Syncopate', sans-serif; font-size: 0.85rem; letter-spacing: 5px; color: hsl(var(--hue), var(--accent-sat), var(--accent-lightness)); }
        .theme-toggle { cursor: pointer; background: var(--border); border: none; padding: 8px 18px; border-radius: 20px; color: inherit; font-family: 'JetBrains Mono'; font-size: 0.72rem; transition: all 0.3s; }
        .theme-toggle:hover { background: hsla(var(--hue), var(--accent-sat), var(--accent-lightness), 0.2); }
        .hero-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }
        .hero-item {
            background: hsla(var(--hue), 20%, 50%, 0.07);
            backdrop-filter: blur(12px);
            padding: 28px 24px;
            border: 1px solid var(--border);
            border-radius: 16px;
            transition: all 0.4s ease;
        }
        .hero-item.clickable { cursor: pointer; }
        .hero-item.clickable:hover {
            border-color: hsl(var(--hue), var(--accent-sat), var(--accent-lightness));
            transform: translateY(-3px);
            box-shadow: 0 10px 25px hsla(var(--hue), 40%, 30%, 0.15);
        }
        .hero-label { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 2.2px; color: #888; margin-bottom: 10px; display: block; }
        .hero-value { font-family: 'JetBrains Mono'; font-size: 1.9rem; font-weight: 500; }
        .content-layout { display: grid; grid-template-columns: 1fr 360px; gap: 32px; }
        .log-list {
            background: hsla(0,0,0,0.05);
            border: 1px solid var(--border);
            border-radius: 14px;
            min-height: 300px;
            padding: 12px;
        }
        .log-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 18px;
            border-bottom: 1px solid var(--border);
            transition: background 0.2s;
        }
        .log-row:hover { background: hsla(var(--hue), 35%, 50%, 0.1); }
        .vulnerability-tag {
            background: hsla(var(--hue), var(--accent-sat), var(--accent-lightness), 0.15);
            color: hsl(var(--hue), var(--accent-sat), var(--accent-lightness));
            border: 1px solid currentColor;
            padding: 3px 10px;
            border-radius: 6px;
            margin-right: 14px;
            font-size: 0.72rem;
            font-weight: 600;
        }
        .log-url { font-family: 'JetBrains Mono'; font-size: 0.84rem; color: inherit; text-decoration: none; word-break: break-all; opacity: 0.94; }
        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 280px;
            color: #777;
            font-family: 'JetBrains Mono';
            font-size: 0.9rem;
            text-align: center;
            padding: 40px;
        }
        .status-box {
            background: hsla(0,0,0,0.05);
            border: 1px solid var(--border);
            padding: 32px 28px;
            border-radius: 20px;
            backdrop-filter: blur(22px);
            position: sticky;
            top: 40px;
        }
        .phase-indicator {
            font-size: 0.8rem;
            margin-bottom: 12px;
            letter-spacing: 1.5px;
            color: hsl(var(--hue), var(--accent-sat), var(--accent-lightness));
            text-transform: uppercase;
            font-weight: 600;
        }
        .progress-track { height: 10px; background: var(--border); margin: 24px 0; border-radius: 10px; overflow: hidden; }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg,
                hsl(var(--hue), var(--accent-sat), calc(var(--accent-lightness) - 18%)),
                hsl(var(--hue), var(--accent-sat), var(--accent-lightness))
            );
            width: 0%;
            transition: width 1s cubic-bezier(0.4,0,0.2,1);
            box-shadow: 0 0 16px hsla(var(--hue), var(--accent-sat), var(--accent-lightness), 0.55);
        }
        .meta-info { font-family: 'JetBrains Mono'; font-size: 0.72rem; opacity: 0.75; margin-top: 16px; line-height: 1.6; }
        .btn-report {
            width: 100%;
            background: hsl(var(--hue), var(--accent-sat), var(--accent-lightness));
            color: white;
            padding: 18px;
            border: none;
            border-radius: 12px;
            font-weight: 700;
            cursor: pointer;
            margin-top: 24px;
            font-size: 0.9rem;
            transition: all 0.3s;
            text-align: center;
            text-decoration: none;
            display: block;
        }
        .btn-report:hover { filter: brightness(1.15); transform: translateY(-2px); }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); backdrop-filter: blur(8px); }
        .modal-content {
            background: hsl(var(--hue), 16%, var(--bg-lightness));
            margin: 8% auto;
            padding: 32px;
            border: 1px solid hsl(var(--hue), var(--accent-sat), var(--accent-lightness));
            border-radius: 20px;
            width: 92%;
            max-width: 720px;
            max-height: 78vh;
            overflow-y: auto;
        }
        .modal-header { font-size: 0.9rem; margin-bottom: 20px; letter-spacing: 2px; color: hsl(var(--hue), var(--accent-sat), var(--accent-lightness)); }
        .endpoint-item { padding: 10px 0; font-family: 'JetBrains Mono'; font-size: 0.78rem; border-bottom: 1px solid var(--border); opacity: 0.88; }
        @media (max-width: 1024px) {
            .hero-grid { grid-template-columns: repeat(2, 1fr); }
            .content-layout { grid-template-columns: 1fr; }
            .app-container { padding: 20px; }
            .status-box { position: static; margin-top: 24px; }
        }
        @media (max-width: 640px) {
            .app-container { padding: 16px; }
            .hero-grid { grid-template-columns: 1fr; gap: 16px; }
            .hero-item { padding: 20px 16px; }
            .hero-value { font-size: 1.6rem; }
            .log-row { flex-direction: column; align-items: flex-start; gap: 10px; padding: 12px; }
            .log-url { font-size: 0.80rem; line-height: 1.4; }
            .vulnerability-tag { font-size: 0.68rem; padding: 4px 8px; }
            .btn-report { padding: 14px; font-size: 0.95rem; }
            .modal-content { margin: 10% 4%; padding: 24px; }
        }
    </style>
</head>
<body data-theme="dark">
    <div class="app-container">
        <nav>
            <div class="logo">HUNTER // ADAPTIVE_INTELLIGENCE</div>
            <div style="display:flex; align-items:center; gap:24px;">
                <button class="theme-toggle" onclick="toggleTheme()">MODE SHIFT</button>
                <div style="font-family:'JetBrains Mono'; font-size:0.72rem; opacity:0.75;">
                    NODE: {{ LOCAL_IP }} • <span id="duration">00:00:00</span>
                </div>
            </div>
        </nav>
        <section class="hero-grid">
            <div class="hero-item"><span class="hero-label">Scope Domains</span><span class="hero-value" id="total-domains">0</span></div>
            <div class="hero-item clickable" onclick="toggleModal('endpoints')"><span class="hero-label">Active Endpoints</span><span class="hero-value" id="alive-domains">0</span></div>
            <div class="hero-item clickable" onclick="toggleModal('findings')"><span class="hero-label">Confirmed Redirects</span><span class="hero-value" id="redirectable" style="color:hsl(var(--hue), var(--accent-sat), var(--accent-lightness));">0</span></div>
            <div class="hero-item"><span class="hero-label">Progress</span><span class="hero-value" id="prog-hero">0%</span></div>
        </section>
        <div class="content-layout">
            <main>
                <div class="log-list" id="url-list">
                    <!-- content inserted dynamically -->
                </div>
            </main>
            <aside>
                <div class="status-box">
                    <div class="phase-indicator" id="phase">INITIALIZING</div>
                    <div class="progress-track"><div class="progress-fill" id="progress"></div></div>
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono'; font-size:0.74rem; opacity:0.8;">
                        <span id="progress-val">0%</span>
                        <span id="last-updated">Just started</span>
                    </div>
                    <div class="meta-info">
                        <div>URLs collected: <span id="urls-collected">—</span></div>
                        <div>Scan started: <span id="scan-start">—</span></div>
                    </div>
                    <a href="/generate-report" class="btn-report">GENERATE PDF REPORT</a>
                </div>
            </aside>
        </div>
    </div>
    <div id="modal" class="modal" onclick="toggleModal()">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header" id="modal-title">DETAILS</div>
            <div id="modal-list"></div>
        </div>
    </div>

    <script>
        const socket = io();
        let findings = [];
        let endpoints = [];
        let startTime = Date.now();

        function toggleTheme() {
            const body = document.body;
            const current = body.getAttribute('data-theme');
            body.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
            updateHue();
        }

        function updateHue() {
            const p = parseFloat(document.getElementById('progress-val').innerText) || 0;
            const isLight = document.body.getAttribute('data-theme') === 'light';
            targetHue = isLight ? (p / 100) * 135 : (p / 100) * 105;
        }

        let targetHue = 0, currentHue = 0;
        function animateColors() {
            currentHue += (targetHue - currentHue) * 0.07;
            document.documentElement.style.setProperty('--hue', Math.round(currentHue));
            requestAnimationFrame(animateColors);
        }
        animateColors();

        socket.on('connect', () => socket.emit('init_request'));

        socket.on('init', (data) => {
            startTime = data.start_time * 1000;
            findings = data.urls || [];
            endpoints = data.subdomains || [];
            renderFindings();
            updateDashboard(data.status);
            updateHue();
            document.getElementById('scan-start').innerText = new Date(startTime).toLocaleString();
        });

        socket.on('status', (data) => {
            updateDashboard(data);
            updateHue();
        });

        socket.on('urls', (data) => {
            findings = data.urls || [];
            endpoints = data.subdomains || [];
            renderFindings();
        });

        function updateDashboard(data) {
            if (!data) return;
            const p = data.progress || 0;
            document.getElementById('total-domains').innerText = data.total_domains || 0;
            document.getElementById('alive-domains').innerText = data.alive_domains || 0;
            const confirmedCount = findings.filter(f => f.classification === "CONFIRMED").length;
            document.getElementById('redirectable').innerText = confirmedCount;
            document.getElementById('prog-hero').innerText = p + '%';
            document.getElementById('progress-val').innerText = p + '%';
            document.getElementById('progress').style.width = p + '%';
            document.getElementById('phase').innerText = (data.phase || 'IDLE').toUpperCase();
            document.getElementById('last-updated').innerText = 'Updated ' + new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
            document.getElementById('urls-collected').innerText = findings.length > 0 ? findings.length : (data.alive_domains > 0 ? 'Scanning...' : '—');
        }

        function renderFindings() {
            const container = document.getElementById('url-list');
            if (!container) return;

            if (!findings || findings.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div style="font-size:1.1rem; margin-bottom:12px; opacity:0.9;">HUNT IN PROGRESS</div>
                        <div style="max-width:420px; line-height:1.5;">
                            Collecting URLs • Filtering parameters • Validating redirects...<br>
                            Confirmed open redirects will appear here.
                        </div>
                    </div>
                `;
                return;
            }

            container.innerHTML = findings.map(f => `
                <div class="log-row">
                    <div style="flex:1; min-width:0;">
                        <span class="vulnerability-tag" style="${getSeverityStyle(f.classification)}">
                            ${f.classification} (${f.severity || '?'})
                        </span>
                        <a href="${f.url}" target="_blank" class="log-url"
                           style="color:${f.classification === 'CONFIRMED' ? '#ff4d4d' : 'inherit'};
                                  font-weight:${f.classification === 'CONFIRMED' ? 'bold' : 'normal'};">
                           ${f.url}
                        </a>
                    </div>
                </div>
            `).join('');
        }

        function getSeverityStyle(type) {
            if (type === "CONFIRMED") return 'background:#d9534f; color:white;';
            if (type === "LIKELY")    return 'background:#f0ad4e; color:white;';
            if (type === "SUSPICIOUS") return 'background:gold; color:black;';
            return 'background:#5cb85c; color:white;';
        }

        function toggleModal(mode = null) {
            const modal = document.getElementById('modal');
            const title = document.getElementById('modal-title');
            const list = document.getElementById('modal-list');
            if (!mode) {
                modal.style.display = 'none';
                return;
            }
            modal.style.display = 'block';
            if (mode === 'endpoints') {
                title.innerText = 'RESOLVED ENDPOINTS';
                list.innerHTML = endpoints.length === 0
                    ? '<div style="text-align:center; padding:40px; color:#777;">No endpoints resolved yet.</div>'
                    : endpoints.map(e => `<div class="endpoint-item">${e}</div>`).join('');
            } else if (mode === 'findings') {
                title.innerText = 'OPEN REDIRECT FINDINGS';
                list.innerHTML = findings.length === 0
                    ? '<div style="text-align:center; padding:40px; color:#777;">No findings yet.<br>Keep hunting!</div>'
                    : findings.map(f => `<div class="endpoint-item"><a href="${f.url}" target="_blank" style="color:inherit; text-decoration:none;">${f.url} (${f.classification} - Sev: ${f.severity || '?'})</a></div>`).join('');
            }
        }

        setInterval(() => {
            const d = Math.floor((Date.now() - startTime) / 1000);
            const h = Math.floor(d/3600).toString().padStart(2,'0');
            const m = Math.floor((d%3600)/60).toString().padStart(2,'0');
            const s = (d%60).toString().padStart(2,'0');
            document.getElementById('duration').innerText = `${h}:${m}:${s}`;
        }, 1000);
    </script>
</body>
</html>"""

# ── Socket Handlers ──
@socketio.on('connect')
def handle_connect():
    logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Client connected – sending init\n")
    logf.flush()
    emit('init', {
        'start_time': START_TIME,
        'urls': get_urls(),
        'subdomains': get_subdomains(),
        'status': get_status()
    })

@socketio.on('init_request')
def handle_init_request():
    emit('init', {
        'start_time': START_TIME,
        'urls': get_urls(),
        'subdomains': get_subdomains(),
        'status': get_status()
    })

# ── File watcher ──
def watch_files():
    last_modified = {}
    watched = [
        STATUS_PATH, CONFIRMED_PATH, LIKELY_PATH, SUSPICIOUS_PATH,
        LIVE_PATH, SUBS_PATH
    ]
    while True:
        changed = False
        for path in watched:
            if os.path.exists(path):
                try:
                    mtime = os.path.getmtime(path)
                    if path not in last_modified or mtime > last_modified[path]:
                        last_modified[path] = mtime
                        changed = True
                except:
                    pass
        if changed:
            logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Files changed – broadcasting\n")
            logf.flush()
            socketio.emit('status', get_status())
            socketio.emit('urls', {'urls': get_urls(), 'subdomains': get_subdomains()})
        time.sleep(0.5)

@app.route("/")
def index():
    return render_template_string(HTML, LOCAL_IP=LOCAL_IP)

if __name__ == "__main__":
    Thread(target=watch_files, daemon=True).start()
    logf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Server running on http://{LOCAL_IP}:{PORT}\n")
    logf.flush()
    socketio.run(app, host="0.0.0.0", port=PORT, debug=False, allow_unsafe_werkzeug=True)
