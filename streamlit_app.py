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
    st.title("carta para jenni")
    user_key = st.text_input("cual es el ingrediente secreto del marinado de carne asada?:", type="password")
    
    if st.button("picale"):
        if user_key == CORRECT_KEY:
            st.session_state["page"] = "upload_page"
        else:
            st.error("nope, la fruta!")

# Page to Upload and Process Image
def upload_page():
    st.title("sube la foto del paso 1. trata de que solo se vea lo que esta enmarcado")
    uploaded_image = st.file_uploader("Upload an image from your camera roll:", type=["jpg", "jpeg", "png"])

    if uploaded_image is not None:
        image = Image.open(uploaded_image)
        image_np = np.array(image)
        st.image(image, caption='', use_column_width=True)
        
        # Load OCR model from easyocr
        reader = easyocr.Reader(['en'])  # Disable GPU to avoid compatibility issues
        st.write("procesando...")
        # Extract text using OCR
        result = reader.readtext(image_np, detail=0)
        extracted_text = " ".join(result)
        
        
        st.write("texto extraido:")
        st.write(extracted_text)
        extracted_text = extracted_text.replace(" ", "")


        extracted_text_bypass = "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"
        
        # Ask user for decryption key
        user_key = st.text_input("lo que copiaste en el paso 2:", type="password")
        if st.button("decodificar"):
            try:
                                    # Decode the user key from base64
                secret_key = base64.urlsafe_b64decode(user_key)

                # Decode the encrypted message from base64
                decoded_data = base64.b64decode(extracted_text_bypass)

                # Extract the IV and ciphertext
                iv = decoded_data[:16]
                ciphertext = decoded_data[16:]

                # Initialize AES in CBC mode with the provided key and IV
                cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))

                # Decrypt the message
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(ciphertext) + decryptor.finalize()

                # Remove padding from the decrypted message
                unpadder = padding.PKCS7(128).unpadder()
                message = unpadder.update(padded_data) + unpadder.finalize()

                # Display the decrypted message
                st.write("vaya vaya, llegaste al final:")
                st.write(message.decode('utf-8'))

            except Exception as e:
                st.error("te equivocaste en el paso 2.")

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
