#!/usr/bin/env python3
"""
EcoVault — Application Web Vulnérable pour le Lab SDV M2
Ne pas utiliser en production.
"""
import os
import re
import time
import hashlib
import subprocess
import threading
from io import BytesIO

import pymysql
import pymongo
import jwt
from flask import (
    Flask, request, render_template, render_template_string,
    redirect, url_for, jsonify, make_response, g
)
from lxml import etree

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-not-for-production'
JWT_SECRET = 'jwt-secret-key-ecovault-2026'
RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcd0xBXh0w16f
wLM8m5l8JqQfLpKzPq5n3bR6wX0hYsT8vK3mN1bR4qWxZ5jL9pM2cR7vS8tY0aB1
nK4xQ6zJ9wV3mD5fH8jL2pR7tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6
zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5
fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0
bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6zJ9mV3pR5fH8jL2tY0bN1kQ4wX6
zQIDAQAB
-----END PUBLIC KEY-----"""

# ═══════════════════════════════════════════════════════════════
#  Helpers — Connexions DB vulnérables
# ═══════════════════════════════════════════════════════════════

def get_db():
    if 'db' not in g:
        g.db = pymysql.connect(
            host='10.0.0.2', user='appuser', password='apppass',
            database='ecovault', charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5
        )
    return g.db

def get_mongo():
    if 'mongo' not in g:
        client = pymongo.MongoClient('mongodb://10.0.0.3:27017/', serverSelectionTimeoutMS=3000)
        g.mongo = client.ecovault
    return g.mongo

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db: db.close()
    mongo = g.pop('mongo', None)
    if mongo is not None: mongo.client.close()

def query_db(query, one=False):
    """Exécute une requête SQL — VOLONTAIREMENT VULNÉRABLE (pas de paramétrage)"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query)
    if one:
        return cur.fetchone()
    return cur.fetchall()

# ═══════════════════════════════════════════════════════════════
#  Routes — Pages principales
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/shop')
def shop():
    products = query_db("SELECT * FROM products")
    comments = query_db("SELECT c.content, c.created_at, u.email FROM comments c JOIN users u ON c.user_id = u.id ORDER BY c.created_at DESC")
    return render_template('shop.html', products=products, comments=comments)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        # ⚠️ SQL INJECTION — Injection volontaire
        sql = f"SELECT * FROM users WHERE email='{email}' AND password='{password}'"
        try:
            user = query_db(sql, one=True)
            if user:
                payload = {
                    'user_id': user['id'],
                    'email': user['email'],
                    'role': user['role'],
                    'kid': 'key1'
                }
                token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('token', token, httponly=False, samesite='Lax')
                return resp
            else:
                error = 'Identifiants invalides'
        except Exception as e:
            error = f'Erreur: {e}'
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('token')
    user = decode_jwt(token)
    if not user:
        return redirect(url_for('login'))
    return render_template('index.html', user=user)

# ═══════════════════════════════════════════════════════════════
#  Module 2 — Injections avancées
# ═══════════════════════════════════════════════════════════════

# ── SQLi : Blind (time/boolean) ──
@app.route('/api/transactions')
def api_transactions():
    """T1190 — Blind SQL Injection"""
    user_filter = request.args.get('filter', '')
    order = request.args.get('order', 'id')
    # ⚠️ SQL INJECTION — Injection volontaire
    sql = f"SELECT t.id, t.amount, t.status, t.created_at FROM transactions t WHERE t.id > 0"
    if user_filter:
        sql += f" AND t.user_id = {user_filter}"
    sql += f" ORDER BY {order}"
    try:
        rows = query_db(sql)
        return jsonify(rows)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── NoSQLi : MongoDB ──
@app.route('/api/export', methods=['POST'])
def api_export():
    """T1190 — NoSQL Injection (MongoDB)"""
    data = request.get_json(force=True, silent=True) or {}
    collection = data.get('collection', 'users')

    # ⚠️ NOSQL INJECTION — Injection volontaire (les opérateurs $ne, $gt passent)
    mongo_filter = data.get('filter', {})

    try:
        mdb = get_mongo()
        col = mdb[collection]
        results = list(col.find(mongo_filter, {'_id': 0}))

        # Seed MongoDB avec quelques données
        if not results:
            col.insert_one({'username': 'admin_mongo', 'password': 'flag{nosqli_mongo_2026}', 'role': 'admin'})
            col.insert_one({'username': 'user_mongo', 'password': 'mongouser123', 'role': 'user'})
            results = list(col.find(mongo_filter, {'_id': 0}))

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── SSTI : Server-Side Template Injection ──
@app.route('/admin/templates', methods=['GET', 'POST'])
def admin_templates():
    """T1190 — SSTI (Jinja2)"""
    token = request.cookies.get('token')
    user = decode_jwt(token)
    if not user or user.get('role') != 'admin':
        return redirect(url_for('login'))

    output = None
    if request.method == 'POST':
        template_name = request.form.get('template_name', '')
        template_body = request.form.get('template_body', '')

        # ⚠️ SSTI — Injection volontaire via render_template_string
        try:
            output = render_template_string(
                f"<h2>Prévisualisation : {template_name}</h2>\n{template_body}"
            )
        except Exception as e:
            output = f"<p style='color:red'>Erreur template : {e}</p>"

    return render_template('admin.html', ssti_output=output)

# ── Command Injection ──
@app.route('/api/ping', methods=['POST'])
def api_ping():
    """T1059.004 — Command Injection"""
    host = request.form.get('host', '') or request.args.get('host', '')
    if not host:
        return jsonify({'error': 'Paramètre host manquant'}), 400

    # ⚠️ COMMAND INJECTION — Injection volontaire
    cmd = f"ping -c 2 {host}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return jsonify({'output': output.decode(errors='replace')})
    except subprocess.CalledProcessError as e:
        return jsonify({'output': e.output.decode(errors='replace')})
    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Timeout'}), 408

# ── XXE : XML External Entity ──
@app.route('/api/upload-xml', methods=['POST'])
def api_upload_xml():
    """T1190 — XXE"""
    xml_data = request.data
    if not xml_data:
        xml_data = request.form.get('xml', '')

    if not xml_data:
        return jsonify({'error': 'Données XML requises'}), 400

    # ⚠️ XXE — Injection volontaire (pas de désactivation des entités externes)
    try:
        parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
        tree = etree.fromstring(xml_data.encode() if isinstance(xml_data, str) else xml_data, parser)
        result = etree.tostring(tree, pretty_print=True).decode()
        return jsonify({'parsed': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
#  Module 3 — Authentification & Logique métier
# ═══════════════════════════════════════════════════════════════

# ── IDOR ──
@app.route('/api/profile/<int:user_id>')
def api_profile(user_id):
    """T1548 / T1134 — IDOR — Aucune vérification d'appartenance"""
    # ⚠️ IDOR — Pas de vérification que user_id == utilisateur connecté
    user = query_db(f"SELECT id, email, role, api_key, created_at FROM users WHERE id={user_id}", one=True)
    if user:
        return jsonify(user)
    return jsonify({'error': 'Utilisateur non trouvé'}), 404

# ── JWT Flaws ──
def decode_jwt(token):
    """Décode un JWT — VOLONTAIREMENT VULNÉRABLE"""
    if not token:
        return None
    try:
        # ⚠️ JWT FLAW — Accepte l'algo 'none' et gère le kid de manière vulnérable
        header = jwt.get_unverified_header(token)

        if header.get('alg') == 'none':
            # Attaque "none algorithm"
            return jwt.decode(token, options={"verify_signature": False})

        kid = header.get('kid', 'key1')

        # ⚠️ JWT FLAW — kid injection (path traversal)
        if '../' in str(kid) or '/dev/' in str(kid):
            # Si le kid pointe vers /dev/null, on utilise une clé vide (bypass)
            if 'null' in str(kid):
                return jwt.decode(token, '', algorithms=['HS256'])
            # Path traversal : on ignore la vérification
            return jwt.decode(token, options={"verify_signature": False})

        # Vérification standard ou RSA/HMAC confusion
        if header.get('alg') in ('HS256', 'HS384', 'HS512'):
            return jwt.decode(token, JWT_SECRET, algorithms=[header['alg']])

        # ⚠️ JWT FLAW — Accepte HMAC avec la clé publique RSA
        if header.get('alg') == 'RS256':
            try:
                return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['RS256'])
            except jwt.InvalidSignatureError:
                # RSA/HMAC confusion : accepte HS256 avec la clé publique comme secret
                try:
                    return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=['HS256'])
                except Exception:
                    pass

        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None

@app.route('/api/jwt-info')
def api_jwt_info():
    """Endpoint public pour récupérer la clé publique RSA (nécessaire pour attaque JWT)"""
    return jsonify({
        'public_key': RSA_PUBLIC_KEY,
        'algorithm': 'RS256',
        'note': 'Clé publique utilisée pour la vérification des signatures JWT'
    })

@app.route('/api/whoami')
def api_whoami():
    token = request.cookies.get('token')
    user = decode_jwt(token)
    return jsonify(user or {'error': 'Non authentifié'})

# ── Race Condition : Transfer ──
transfer_lock = threading.Lock()
transfer_used = set()

@app.route('/api/transfer', methods=['POST'])
def api_transfer():
    """T1068 — Race Condition (TOCTOU)"""
    coupon = request.form.get('coupon', '')
    amount = float(request.form.get('amount', 0))

    # ⚠️ RACE CONDITION — Délai volontaire entre check et use
    if coupon:
        try:
            coupon_info = query_db(f"SELECT * FROM coupons WHERE code='{coupon}'", one=True)
            if coupon_info and not coupon_info['used']:
                # Vérification OK
                # ⚠️ Délai volontaire pour exploiter la race condition
                time.sleep(1)
                # Marquer comme utilisé
                query_db(f"UPDATE coupons SET used=TRUE WHERE code='{coupon}'")
                discount = amount * coupon_info['discount_percent'] / 100
                return jsonify({
                    'success': True,
                    'original': amount,
                    'discount': discount,
                    'final': amount - discount,
                    'coupon': coupon
                })
            else:
                return jsonify({'error': 'Coupon déjà utilisé ou invalide'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'Coupon requis'}), 400

# ── Business Logic : Order ──
@app.route('/api/order', methods=['POST'])
def api_order():
    """Business Logic — Price manipulation, integer overflow"""
    data = request.get_json(force=True, silent=True) or {}
    product_id = data.get('product_id', 0)
    quantity = data.get('quantity', 1)
    # ⚠️ BUSINESS LOGIC — Le prix est fourni par le client
    price = float(data.get('price', 0))

    if price <= 0:
        # ⚠️ BUSINESS LOGIC — Integer overflow possible
        total = int(data.get('total', 0))
        if total < 0:
            return jsonify({'success': True, 'message': 'flag{business_logic_overflow_2026}', 'credit': abs(total)})

    return jsonify({
        'success': True,
        'product_id': product_id,
        'quantity': quantity,
        'price': price,
        'total': quantity * price,
        'message': 'Commande enregistrée'
    })

# ── CSRF : Change Password ──
@app.route('/admin/change-password', methods=['POST'])
def admin_change_password():
    """T1539 — CSRF — Pas de token CSRF"""
    token = request.cookies.get('token')
    user = decode_jwt(token)
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'Non autorisé'}), 403

    new_password = request.form.get('new_password', '')
    if not new_password:
        return jsonify({'error': 'Mot de passe requis'}), 400

    # ⚠️ CSRF — Aucun token anti-CSRF, le cookie de session est envoyé automatiquement
    query_db(f"UPDATE users SET password='{new_password}' WHERE id={user['user_id']}")
    return jsonify({'success': True, 'message': 'Mot de passe changé'})

# ═══════════════════════════════════════════════════════════════
#  Module 4 — Exploitation combinée
# ═══════════════════════════════════════════════════════════════

# ── Stored XSS ──
@app.route('/shop/comment', methods=['POST'])
def shop_comment():
    """T1189 — Stored XSS"""
    product_id = request.form.get('product_id', 0)
    content = request.form.get('content', '')

    # ⚠️ STORED XSS — Pas d'échappement HTML
    token = request.cookies.get('token')
    user = decode_jwt(token)
    user_id = user['user_id'] if user else 1

    query_db(f"INSERT INTO comments (user_id, product_id, content) VALUES ({user_id}, {product_id}, '{content}')")
    return redirect(url_for('shop'))

# ── Reflected XSS ──
@app.route('/search')
def search():
    """T1189 — Reflected XSS"""
    q = request.args.get('q', '')
    products = query_db(f"SELECT * FROM products WHERE name LIKE '%{q}%'") if q else []

    # ⚠️ REFLECTED XSS — q réinjecté sans échappement
    html = f"<h3>Résultats pour : {q}</h3>"
    html += "<ul>"
    for p in products or []:
        html += f"<li>{p['name']} — {p['price']}€</li>"
    html += "</ul>"
    if not products:
        html += "<p>Aucun résultat.</p>"
    return html

# ── File Upload (Webshell) ──
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/admin/upload', methods=['GET', 'POST'])
def admin_upload():
    """T1505.003 — Webshell upload"""
    token = request.cookies.get('token')
    user = decode_jwt(token)
    if not user or user.get('role') != 'admin':
        return redirect(url_for('login'))

    message = None
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = file.filename
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)

            # ⚠️ UPLOAD FLAW — Aucune vérification d'extension
            message = f"Fichier uploadé : {filename}"
        else:
            message = "Aucun fichier sélectionné"

    return render_template('admin.html', upload_msg=message)

# ═══════════════════════════════════════════════════════════════
#  Module 5 — Bonus / Debug
# ═══════════════════════════════════════════════════════════════

@app.route('/admin/debug')
def admin_debug():
    """Endpoint de debug exposé — contient des informations sensibles"""
    token = request.cookies.get('token')
    user = decode_jwt(token)
    if not user or user.get('role') != 'admin':
        return jsonify({'error': 'Admin requis'}), 403

    return jsonify({
        'internal_hosts': ['10.0.0.10:8081', '10.0.0.10:25'],
        'hint': 'Le serveur SMTP interne contient des messages sensibles',
        'flag_4': 'flag{ssti_rce_admin_2026}' if user else 'Non disponible'
    })

@app.route('/health')
def health():
    return jsonify({'status': 'UP'})

# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
