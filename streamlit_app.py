import streamlit as st
import easyocr
import base64
from PIL import Image
import numpy as np

# Define correct key for demonstration
CORRECT_KEY = "correct_password"

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
        reader = easyocr.Reader(['en'])  # English language reader
        st.write("Processing image...")
        # Extract text using OCR
        result = reader.readtext(image_np, detail=0)
        extracted_text = " ".join(result)
        
        st.write("Extracted text:")
        st.write(extracted_text)
        
        # Ask user for encryption key
        user_key = st.text_input("Paste your decryption key to decode the transcribed text:", type="password")
        if st.button("Decode Text"):
            try:
                decoded_text = base64.b64decode(extracted_text.encode('utf-8')).decode('utf-8')
                st.write("Decoded text:")
                st.write(decoded_text)
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
