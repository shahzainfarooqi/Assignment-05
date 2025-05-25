import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib

# Helper: Derive a Fernet key from passkey
def get_fernet(passkey: str) -> Fernet:
    key = hashlib.sha256(passkey.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)

# Initialize session state
if 'authorized' not in st.session_state:
    st.session_state.authorized = False
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}  # {title: encrypted_data}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# Sidebar with usage instructions
st.sidebar.title("📘 Instructions")
st.sidebar.markdown("""
### 🔐 How This App Works
1. Use the password `admin123` to log in.
2. Store any text securely by setting a secret passkey.
3. Retrieve your data by selecting the title and entering the same passkey.
4. After **3 failed decryption attempts**, you'll be logged out.
5. **All data is in memory** and will disappear when the app restarts.

### 💡 Tips
- Choose a unique title for each piece of data.
- Remember your encryption passkey – it's the only way to unlock your data!
""")

# Login page
if not st.session_state.authorized:
    st.title("🔐 Secure Data Vault - Login")
    password = st.text_input("Enter master password to access vault", type="password")
    if st.button("Login"):
        if password == "admin123":
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully!")
        else:
            st.error("Incorrect password.")
    st.stop()  # This stops the script here if not logged in

# Main app UI
st.title("🧠 In-Memory Secure Data Vault")
st.subheader("Store Data")
data_title = st.text_input("Data Title")
data_content = st.text_area("Enter your data")
store_passkey = st.text_input("Passkey to encrypt data", type="password")
if st.button("Store Data"):
    if data_title and data_content and store_passkey:
        fernet = get_fernet(store_passkey)
        encrypted = fernet.encrypt(data_content.encode())
        st.session_state.data_store[data_title] = encrypted
        st.success(f"Data stored securely under title: {data_title}")
    else:
        st.warning("All fields are required to store data.")

st.markdown("---")
st.subheader("Retrieve or Delete Data")
if not st.session_state.data_store:
    st.info("No data stored yet.")
else:
    selected_title = st.selectbox("Select data to retrieve or delete", list(st.session_state.data_store.keys()))
    retrieve_passkey = st.text_input("Enter passkey to decrypt", type="password")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("Retrieve Data"):
            fernet = get_fernet(retrieve_passkey)
            try:
                decrypted = fernet.decrypt(st.session_state.data_store[selected_title]).decode()
                st.success("Data decrypted successfully!")
                st.code(decrypted)
                st.session_state.failed_attempts = 0  # reset on success
            except InvalidToken:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"Incorrect passkey. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("Too many failed attempts. You have been logged out.")
                    st.stop()  # Stop further actions (log out the user)

    with col2:
        if st.button("Delete Data"):
            del st.session_state.data_store[selected_title]
            st.success(f"Data titled '{selected_title}' has been deleted.")
            st.experimental_rerun()  # This will reset the app and remove deleted data

st.markdown("---")
st.caption("🔒 All data is stored securely in memory and cleared when the app is reset.")