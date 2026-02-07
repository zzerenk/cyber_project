from flask import Blueprint, request, jsonify, render_template # <--- render_template EKLENDİ
from app.core.scanner import NmapScanner
import threading
import uuid
import time

# Blueprint tanımlıyoruz
api = Blueprint('api', __name__)

# Geçici Hafıza (Task Listesi)
SCAN_TASKS = {}

# --- 1. EKSİK OLAN PARÇA: ANA SAYFA ROTASI ---
@api.route('/')
def index():
    # Tarayıcı siteye girince home.html'i gösterir
    return render_template('pages/home.html')


# --- 2. ASENKRON İŞÇİ (Arka Plan Görevi) ---
def run_scan_in_background(task_id, target, options):
    scanner = NmapScanner()
    
    SCAN_TASKS[task_id]['status'] = 'running'
    SCAN_TASKS[task_id]['message'] = '🕵️‍♂️ Dedektif olay yerine intikal ediyor (Nmap Başlatılıyor)...'
    SCAN_TASKS[task_id]['progress'] = 10
    
    try:
        # Taramayı Yap
        result = scanner.scan_target(target, options)
        
        # Bitiş Durumu
        SCAN_TASKS[task_id]['status'] = 'completed'
        SCAN_TASKS[task_id]['message'] = '✅ Kanıtlar toplandı, rapor hazır.'
        SCAN_TASKS[task_id]['progress'] = 100
        SCAN_TASKS[task_id]['result'] = result

    except Exception as e:
        SCAN_TASKS[task_id]['status'] = 'failed'
        SCAN_TASKS[task_id]['message'] = f'❌ Bir hata oluştu: {str(e)}'
        SCAN_TASKS[task_id]['progress'] = 0


# --- 3. API ENDPOINTLERİ (Başlarına /api ekledik) ---

@api.route('/api/scan', methods=['POST']) # <--- Adres /api/scan oldu
def start_scan():
    data = request.get_json()
    target = data.get('target')
    options = data.get('options', {})

    if not target:
        return jsonify({"success": False, "error": "Hedef belirtilmedi"}), 400

    task_id = str(uuid.uuid4())
    
    SCAN_TASKS[task_id] = {
        'status': 'pending',
        'message': 'Sıraya alındı...',
        'progress': 0,
        'result': None
    }

    thread = threading.Thread(target=run_scan_in_background, args=(task_id, target, options))
    thread.start()

    return jsonify({"success": True, "task_id": task_id})

@api.route('/api/status/<task_id>', methods=['GET']) # <--- Adres /api/status/... oldu
def check_status(task_id):
    task = SCAN_TASKS.get(task_id)
    
    if not task:
        return jsonify({"success": False, "error": "Böyle bir görev bulunamadı"}), 404
        
    return jsonify(task)