from flask import Flask, request, render_template, send_file, redirect, url_for, flash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
#pip install flask cryptography - jeśli flask powyżej nie jest rozpoznany w kodzie, wpisać w terminal to polecenie
#python app.py - uruchomienie aplikacji
#http://127.0.0.1:5000 - na tej stronie wyświetla się mechanizm podpisu cyfrowego
app = Flask(__name__)
app.secret_key = 'supersecretkey'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
SIGNATURE_FILE = os.path.join(BASE_DIR, 'signature.bin')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open(os.path.join(KEYS_DIR, "private_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(os.path.join(KEYS_DIR, "public_key.pem"), "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys_route():
    generate_keys()
    flash("Klucze wygenerowane pomyślnie.")
    return redirect(url_for('index'))

@app.route('/sign', methods=['POST'])
def sign():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    with open(file_path, "rb") as f:
        data = f.read()

    # Oblicz skrót wiadomości
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data)
    hash_value = digest.finalize()

    with open(os.path.join(KEYS_DIR, "private_key.pem"), "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Podpisz skrót wiadomości kluczem prywatnym
    signature = private_key.sign(
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(SIGNATURE_FILE, "wb") as f:
        f.write(signature)
    
    flash("Plik pomyślnie podpisany. Podpis został pobrany")
    return send_file(SIGNATURE_FILE, as_attachment=True)

@app.route('/verify', methods=['POST'])
def verify():
    if 'file' not in request.files or 'signature' not in request.files:
        flash('No file or signature part')
        return redirect(request.url)
    
    file = request.files['file']
    signature_file = request.files['signature']

    if file.filename == '' or signature_file.filename == '':
        flash('No selected file or signature')
        return redirect(request.url)

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    signature_path = os.path.join(UPLOAD_FOLDER, signature_file.filename)

    file.save(file_path)
    signature_file.save(signature_path)

    with open(file_path, "rb") as f:
        data = f.read()
    
    with open(signature_path, "rb") as f:
        signature = f.read()

    with open(os.path.join(KEYS_DIR, "public_key.pem"), "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Oblicz skrót wiadomości
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(data)
    hash_value = digest.finalize()

    try:
        # Odszyfruj skrót podpisu i porównaj z obliczonym skrótem
        public_key.verify(
            signature,
            hash_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        flash("PODPIS JEST AUTENTYCZNY")
    except Exception as e:
        flash("PODPIS NIE JEST AUTENTYCZNY")

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
