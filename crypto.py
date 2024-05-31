import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np
import os
import json
import hashlib
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import datetime

class HomomorphicsEncryption:
    def __init__(self, alpha, beta, gamma):
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma

    def decrypt(self, encrypted_image):
        encrypted_image = encrypted_image.astype(np.float32)
        image = (encrypted_image - self.gamma) / self.alpha
        log_image = np.log1p(image)
        fft_image = np.fft.fft2(log_image)
        shifted_fft = np.fft.fftshift(fft_image)

        rows, cols = image.shape[:2]
        center_row, center_col = rows // 2, cols // 2
        filter = np.zeros((rows, cols), dtype=np.float32)
        filter[center_row-10:center_row+10, center_col-10:center_col+10] = 1

        filtered_fft = shifted_fft * filter
        shifted_ifft = np.fft.ifftshift(filtered_fft)
        ifft_image = np.fft.ifft2(shifted_ifft)
        decrypted_image = np.expm1(np.real(ifft_image))
        decrypted_image = np.clip(decrypted_image, 0, 255).astype(np.uint8)

        return decrypted_image

def lorenz_map(x, y, z, a, b, c, iterations):
    for _ in range(iterations):
        x_new = a * (y - x)
        y_new = x * (b - z) - y
        z_new = x * y - c * z
        x, y, z = x_new, y_new, z_new
    return x, y, z

def rossler_map(x, y, z, a, b, c, iterations):
    for _ in range(iterations):
        x_new = -y - z
        y_new = x + a * y
        z_new = b + z * (x - c)
        x, y, z = x_new, y_new, z_new
    return x, y, z

def generate_chaotic_sequence(seed1, seed2, a1, b1, c1, a2, b2, c2, iterations1, iterations2, size):
    sequence = np.zeros(size)
    x1, y1, z1 = seed1
    x2, y2, z2 = seed2
    for i in range(size):
        x1, y1, z1 = lorenz_map(x1, y1, z1, a1, b1, c1, iterations1)
        x2, y2, z2 = rossler_map(x2, y2, z2, a2, b2, c2, iterations2)
        sequence[i] = x1 + y1 + z1 + x2 + y2 + z2
    return sequence

def derive_key(password, salt, length, iterations=500000):
    return pbkdf2_hmac('sha512', password.encode(), salt.encode(), iterations, length)

def rsa_key_pair():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(private_key, ciphertext):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(ciphertext)

def chaos_encrypt(file_path, password, salt, public_key, alpha, beta, gamma, a1, b1, c1, a2, b2, c2, iterations1, iterations2, block_size=16):
    with open(file_path, 'rb') as f:
        plaintext_bytes = f.read()

    padded_plaintext = pad(plaintext_bytes, block_size)

    aes_key = get_random_bytes(32)  # 256-bit AES key
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    ciphertext_bytes = cipher_aes.encrypt(padded_plaintext)

    encrypted_aes_key = rsa_encrypt(public_key, aes_key)

    key = derive_key(password, salt + str(alpha) + str(beta) + str(gamma), 96)
    seed1 = (
        int.from_bytes(key[:32], 'big') / 2**256,
        int.from_bytes(key[32:64], 'big') / 2**256,
        int.from_bytes(key[64:96], 'big') / 2**256
    )
    seed2 = (
        int.from_bytes(key[:32], 'big') / 2**256,
        int.from_bytes(key[32:64], 'big') / 2**256,
        int.from_bytes(key[64:96], 'big') / 2**256
    )

    chaotic_sequence = generate_chaotic_sequence(seed1, seed2, a1, b1, c1, a2, b2, c2, iterations1, iterations2, len(ciphertext_bytes))
    chaotic_bytes = (chaotic_sequence * 255).astype(np.uint8)
    combined_ciphertext = bytearray(len(ciphertext_bytes))

    for i in range(len(ciphertext_bytes)):
        combined_ciphertext[i] = ciphertext_bytes[i] ^ chaotic_bytes[i]

    return encrypted_aes_key, iv, combined_ciphertext

def chaos_decrypt(encrypted_aes_key, iv, combined_ciphertext, password, salt, private_key, alpha, beta, gamma, a1, b1, c1, a2, b2, c2, iterations1, iterations2, block_size=16):
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

    key = derive_key(password, salt + str(alpha) + str(beta) + str(gamma), 96)
    seed1 = (
        int.from_bytes(key[:32], 'big') / 2**256,
        int.from_bytes(key[32:64], 'big') / 2**256,
        int.from_bytes(key[64:96], 'big') / 2**256
    )
    seed2 = (
        int.from_bytes(key[:32], 'big') / 2**256,
        int.from_bytes(key[32:64], 'big') / 2**256,
        int.from_bytes(key[64:96], 'big') / 2**256
    )

    chaotic_sequence = generate_chaotic_sequence(seed1, seed2, a1, b1, c1, a2, b2, c2, iterations1, iterations2, len(combined_ciphertext))
    chaotic_bytes = (chaotic_sequence * 255).astype(np.uint8)
    decrypted_bytes = bytearray(len(combined_ciphertext))

    for i in range(len(combined_ciphertext)):
        decrypted_bytes[i] = combined_ciphertext[i] ^ chaotic_bytes[i]

    decrypted_plaintext = cipher_aes.decrypt(decrypted_bytes)
    return unpad(decrypted_plaintext, block_size)

def extract_image_parameters(image_path, blocks=4):
    image = Image.open(image_path).convert('L')
    image_array = np.array(image)
    h, w = image_array.shape
    block_h, block_w = h // blocks, w // blocks
    params = []
    for i in range(blocks):
        for j in range(blocks):
            block = image_array[i * block_h:(i + 1) * block_h, j * block_w:(j + 1) * block_w]
            alpha = np.mean(block) / 255.0
            beta = np.var(block) / 255.0
            gamma = np.std(block) / 255.0
            params.append((alpha, beta, gamma))
    return params

def save_parameters(folder_path, params):
    with open(os.path.join(folder_path, 'parameters.json'), 'w') as f:
        json.dump(params, f, indent=4)

def save_encrypted_text(folder_path, encrypted_text):
    with open(os.path.join(folder_path, 'crypto.dat'), 'wb') as f:
        f.write(encrypted_text)

def save_decrypted_text(folder_path, decrypted_text, original_file_name):
    with open(os.path.join(folder_path, original_file_name), 'wb') as f:
        f.write(decrypted_text)

def create_output_folder(prefix="encryption"):
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    folder_name = f"{prefix}_{timestamp}"
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

def encrypt():
    try:
        file_path = filedialog.askopenfilename(title="Select File")
        if not file_path:
            return

        image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image files", "*.jpg;*.jpeg;*.png;*.bmp")])
        if not image_path:
            return

        params = extract_image_parameters(image_path)
        param_str = ''.join([f"{alpha},{beta},{gamma};" for alpha, beta, gamma in params])

        password = password_input.get()
        salt = hashlib.sha256(get_random_bytes(32)).hexdigest()

        a1, b1, c1 = float(a1_input.get()), float(b1_input.get()), float(c1_input.get())
        a2, b2, c2 = float(a2_input.get()), float(b2_input.get()), float(c2_input.get())
        iterations1, iterations2 = int(iterations1_input.get()), int(iterations2_input.get())

        private_key, public_key = rsa_key_pair()

        folder_path = create_output_folder()

        alpha, beta, gamma = params[0]
        encrypted_aes_key, iv, combined_ciphertext = chaos_encrypt(file_path, password, salt, public_key, alpha, beta, gamma, a1, b1, c1, a2, b2, c2, iterations1, iterations2)

        params_dict = {
            "params": param_str,
            "a1": a1,
            "b1": b1,
            "c1": c1,
            "a2": a2,
            "b2": b2,
            "c2": c2,
            "iterations1": iterations1,
            "iterations2": iterations2,
            "iv": iv.hex(),
            "encrypted_aes_key": encrypted_aes_key.hex(),
            "public_key": public_key.decode(),
            "private_key": private_key.decode()
        }

        save_parameters(folder_path, params_dict)
        save_encrypted_text(folder_path, combined_ciphertext)

        messagebox.showinfo("Success", f"Encryption successful, files saved to {folder_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt():
    try:
        folder_path = filedialog.askdirectory(title="Select Encrypted Folder")
        if not folder_path:
            return

        with open(os.path.join(folder_path, 'parameters.json'), 'r') as f:
            params = json.load(f)

        param_str = params["params"]
        param_list = param_str.split(';')[:-1]
        image_params = [(float(p.split(',')[0]), float(p.split(',')[1]), float(p.split(',')[2])) for p in param_list]

        password = password_input.get()
        salt = salt_input.get()

        alpha, beta, gamma = image_params[0]
        a1, b1, c1 = float(params["a1"]), float(params["b1"]), float(params["c1"])
        a2, b2, c2 = float(params["a2"]), float(params["b2"]), float(params["c2"])
        iterations1, iterations2 = int(params["iterations1"]), int(params["iterations2"])
        iv = bytes.fromhex(params["iv"])
        encrypted_aes_key = bytes.fromhex(params["encrypted_aes_key"])
        private_key = params["private_key"].encode()

        with open(os.path.join(folder_path, 'crypto.dat'), 'rb') as f:
            combined_ciphertext = f.read()

        decrypted_bytes = chaos_decrypt(encrypted_aes_key, iv, combined_ciphertext, password, salt, private_key, alpha, beta, gamma, a1, b1, c1, a2, b2, c2, iterations1, iterations2)

        original_file_name = os.path.basename(folder_path).replace('encryption', 'decryption')
        decrypted_folder_path = create_output_folder("decryption")
        save_decrypted_text(decrypted_folder_path, decrypted_bytes, original_file_name)

        messagebox.showinfo("Success", f"Decryption successful, files saved to {decrypted_folder_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

app = tk.Tk()
app.title("Hybrid Encryption Program")

tk.Label(app, text="Password:").grid(row=0, column=0, padx=10, pady=5)
password_input = tk.Entry(app, show="*", width=50)
password_input.grid(row=0, column=1, padx=10, pady=5)

tk.Label(app, text="Salt:").grid(row=1, column=0, padx=10, pady=5)
salt_input = tk.Entry(app, width=50)
salt_input.grid(row=1, column=1, padx=10, pady=5)

tk.Label(app, text="a1:").grid(row=2, column=0, padx=10, pady=5)
a1_input = tk.Entry(app, width=50)
a1_input.grid(row=2, column=1, padx=10, pady=5)

tk.Label(app, text="b1:").grid(row=3, column=0, padx=10, pady=5)
b1_input = tk.Entry(app, width=50)
b1_input.grid(row=3, column=1, padx=10, pady=5)

tk.Label(app, text="c1:").grid(row=4, column=0, padx=10, pady=5)
c1_input = tk.Entry(app, width=50)
c1_input.grid(row=4, column=1, padx=10, pady=5)

tk.Label(app, text="a2:").grid(row=5, column=0, padx=10, pady=5)
a2_input = tk.Entry(app, width=50)
a2_input.grid(row=5, column=1, padx=10, pady=5)

tk.Label(app, text="b2:").grid(row=6, column=0, padx=10, pady=5)
b2_input = tk.Entry(app, width=50)
b2_input.grid(row=6, column=1, padx=10, pady=5)

tk.Label(app, text="c2:").grid(row=7, column=0, padx=10, pady=5)
c2_input = tk.Entry(app, width=50)
c2_input.grid(row=7, column=1, padx=10, pady=5)

tk.Label(app, text="Iterations 1:").grid(row=8, column=0, padx=10, pady=5)
iterations1_input = tk.Entry(app, width=50)
iterations1_input.grid(row=8, column=1, padx=10, pady=5)

tk.Label(app, text="Iterations 2:").grid(row=9, column=0, padx=10, pady=5)
iterations2_input = tk.Entry(app, width=50)
iterations2_input.grid(row=9, column=1, padx=10, pady=5)

tk.Button(app, text="Encrypt", command=encrypt, bg="lightblue", fg="black", font=("Arial", 12)).grid(row=10, column=0, padx=10, pady=5)
tk.Button(app, text="Decrypt", command=decrypt, bg="lightgreen", fg="black", font=("Arial", 12)).grid(row=10, column=1, padx=10, pady=5)

app.mainloop()
