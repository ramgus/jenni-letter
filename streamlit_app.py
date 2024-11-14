import streamlit as st
import easyocr
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os
import base64

# Define correct key for demonstration
CORRECT_KEY = "papaya"

# Initial Page to Enter Key
def main_page():
    st.title("Secure OCR App")
    user_key = st.text_input("Enter your key:", type="password")
    
    if st.button("Submit"):
        if user_key == CORRECT_KEY:
            st.session_state["page"] = "upload_page"
        else:
            st.error("Incorrect key. Please try again.")

# Page to Upload and Process Image
def upload_page():
    st.title("Upload Image for OCR")
    uploaded_image = st.file_uploader("Upload an image from your camera roll:", type=["jpg", "jpeg", "png"])

    if uploaded_image is not None:
        image = Image.open(uploaded_image)
        image_np = np.array(image)
        st.image(image, caption='Uploaded Image', use_column_width=True)
        
        # Load OCR model from easyocr
        reader = easyocr.Reader(['en'], gpu=False)  # Disable GPU to avoid compatibility issues
        st.write("Processing image...")
        # Extract text using OCR
        result = reader.readtext(image_np, detail=0)
        extracted_text = " ".join(result)
        
        st.write("Extracted text:")
        st.write(extracted_text)
        
        # Ask user for decryption key
        user_key = st.text_input("Paste your derived decryption key:", type="password")
        if st.button("Decode Text"):
            try:
                # Decode the base64 encoded extracted text (assuming it was encoded before encryption)
                decoded_data = base64.b64decode(extracted_text)
                
                # Extract salt, iv, and ciphertext
                salt = decoded_data[:16]
                iv = decoded_data[16:32]
                ciphertext = decoded_data[32:]
                
                # Derive the same 256-bit key using the secret key and salt
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(user_key.encode())

                # Initialize AES in CBC mode with the IV
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

                # Decrypt the message
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(ciphertext) + decryptor.finalize()

                # Remove padding from the decrypted message
                unpadder = padding.PKCS7(128).unpadder()
                message = unpadder.update(padded_data) + unpadder.finalize()

                st.write("Decoded text:")
                st.write(message.decode())
            except Exception as e:
                st.error("Invalid decryption key or text could not be decoded.")

# Page switch logic
def main():
    if "page" not in st.session_state:
        st.session_state["page"] = "main"
    
    if st.session_state["page"] == "main":
        main_page()
    elif st.session_state["page"] == "upload_page":
        upload_page()

if __name__ == "__main__":
    main()
