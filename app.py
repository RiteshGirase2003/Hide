from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from PIL import Image
from cryptography.fernet import Fernet
import io

app = Flask(__name__)
CORS(app)  # Enable CORS for all domains on all routes

# Helper functions for encryption/decryption
def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

def text_to_binary(data_bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def binary_to_bytes(binary_data):
    bytes_list = []
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if byte == '11111110':
            break
        bytes_list.append(int(byte, 2))
    return bytes(bytes_list)

@app.route('/api-check', methods=['GET'])
def api_check():
    return jsonify({'msg': 'working'}), 200

    
@app.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    if 'image' not in request.files or 'message' not in request.form:
        return jsonify({'error': 'Image file and message are required'}), 400

    image_file = request.files['image']
    secret_message = request.form['message']
    
    key = generate_key()
    encrypted_message = encrypt_message(secret_message, key)
    combined_data = key + b'|||' + encrypted_message
    binary_data = text_to_binary(combined_data) + '1111111111111110'

    # Open the image in memory
    img = Image.open(image_file).convert('RGB')
    pixels = list(img.getdata())
    data_index = 0
    new_pixels = []

    # Modify the image pixels to embed the binary data
    for pixel in pixels:
        r, g, b = pixel
        new_pixel = []
        for color in (r, g, b):
            if data_index < len(binary_data):
                color = (color & ~1) | int(binary_data[data_index])
                data_index += 1
            new_pixel.append(color)
        new_pixels.append(tuple(new_pixel))

    img.putdata(new_pixels)

    # Save the image in memory instead of saving to disk
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)

    # Return the image directly as a response
    return send_file(img_byte_arr, mimetype='image/png',
                     download_name='encrypted_image.png', as_attachment=True,
                     headers={'X-Encryption-Key': key.decode()})


@app.route('/decrypt', methods=['POST'])
def decrypt_endpoint():
    if 'image' not in request.files:
        return jsonify({'error': 'Image file is required'}), 400

    image_file = request.files['image']
    
    # Open the image in memory
    img = Image.open(image_file).convert('RGB')
    pixels = list(img.getdata())

    # Extract the binary data from the image
    binary_data = ''
    for pixel in pixels:
        for color in pixel:
            binary_data += str(color & 1)

    # Convert the binary data to bytes
    hidden_bytes = binary_to_bytes(binary_data)

    # Check if the hidden data contains the expected delimiter
    if b'|||' not in hidden_bytes:
        return jsonify({'error': 'No valid hidden data found'}), 400

    key, encrypted_msg = hidden_bytes.split(b'|||', 1)

    try:
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_msg)
        return jsonify({
            'message': decrypted.decode(),
            'key_used': key.decode()
        })
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
