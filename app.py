import numpy as np
import streamlit as st
import cv2
import tensorflow as tf
from io import BytesIO
import sqlite3
import bcrypt

# Initialize SQLite database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create users table if it doesn't exist
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
)
''')
conn.commit()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def signup(username, password):
    # Check if user already exists
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    if c.fetchone():
        return False
    else:
        # Hash the password and store the user
        hashed_password = hash_password(password)
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return True

def login(username, password):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if user and verify_password(password, user[1]):
        return True
    else:
        return False

# Initialize the database connection
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()

# Create the users table if it doesn't exist
c.execute('''
CREATE TABLE IF NOT EXISTS users(
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')
conn.commit()

# ... (Other function definitions remain unchanged)

def add_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        c.execute('INSERT INTO users(username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def check_user(username, password):
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    if result:
        return bcrypt.checkpw(password.encode('utf-8'), result[0])
    return False

def show_signup():
    st.write("### Sign Up to Tuberculosis Detection")
    new_username = st.text_input("Username", key="new_username")
    new_password = st.text_input("Password", type="password", key="new_password")
    if st.button("Sign Up"):
        if new_username and new_password:
            if add_user(new_username, new_password):
                st.success("Account created successfully! Please log in.")
                st.session_state['current_page'] = 'login'
                st.rerun()
            else:
                st.error("Username already exists. Please try a different one.")
        else:
            st.error("Please enter a username and password.")

def show_login():
    st.write("### Log In")
    username = st.text_input("Username", key="username")
    password = st.text_input("Password", type="password", key="password")
    if st.button("Log In"):
        if check_user(username, password):
            st.session_state['logged_in'] = True
            st.rerun()
        else:
            st.error("Wrong credentials or user does not exist.")

def model():
    # Set the title of the app
    #st.title('Tuberculosis Detection using Deep Learning')
    # File uploader widget
    input_file_name = st.file_uploader("Choose an image...", type=["jpg", "jpeg", "png"])

    if input_file_name is not None:
        # Convert the file to a numpy array
        file_bytes = np.asarray(bytearray(input_file_name.read()), dtype=np.uint8)
        image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        
        # Display the uploaded image
        st.image(image, caption="Chest X-Ray", use_column_width=True)

        # Resize and preprocess the image
        image = cv2.resize(image, (64, 64))
        image = image / 255.0
        image = np.array([image])

        # Load your model
        model = tf.keras.models.load_model('t_model.pt')

        # Make a prediction
        prediction = model.predict(image)

        # Display the prediction result
        if prediction * 100 >= 1:
            st.write("Tuberculosis Detected")
        else:
            st.write("Tuberculosis Not Detected")
if __name__=='__main__':
    st.title('Tuberculosis Detection using Deep Learning')


    auth_status = st.session_state.get('auth_status', None)
    if auth_status == "logged_in":
        st.success(f"Welcome {st.session_state.username}!")
        st.header('Upload an image and the model will detect tuberculosis')
        model()
        
    elif auth_status == "login_failed":
        st.error("Login failed. Please check your username and password.")
        auth_status = None
    elif auth_status == "signup_failed":
        st.error("Signup failed. Username already exists.")
        auth_status = None
    # Login/Signup form
    if auth_status is None or auth_status == "logged_out":
        form_type = st.radio("Choose form type:", ["Login", "Signup"])

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if form_type == "Login":
            if st.button("Login"):
                if login(username, password):
                    st.session_state.auth_status = "logged_in"
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.session_state.auth_status = "login_failed"
                    st.rerun()
        else:  # Signup
            if st.button("Signup"):
                if signup(username, password):
                    st.session_state.auth_status = "logged_in"
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.session_state.auth_status = "signup_failed"
                    st.rerun()

    # Logout button
    if auth_status == "logged_in":
        if st.button("Logout"):
            st.session_state.auth_status = "logged_out"
            del st.session_state.username
            st.rerun()

