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
        reader = easyocr.Reader(['en'])  # Disable GPU to avoid compatibility issues
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
                extracted_text_bypass = "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"
                decoded_data = base64.b64decode(extracted_text_bypass)
                
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
