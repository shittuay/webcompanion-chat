import streamlit as st
import sqlite3
import os
import time
import hashlib
import ollama as ol

# Initialize the SQLite database
DB_PATH = 'chat_history.db'
USER_DB_PATH = 'user_accounts.db'

def init_db():
    # Initialize chat history database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            content TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

    # Initialize user accounts database
    conn = sqlite3.connect(USER_DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(email, username, password):
    conn = sqlite3.connect(USER_DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)', 
                  (email, username, hash_password(password)))
        conn.commit()
    except sqlite3.IntegrityError as e:
        if 'email' in str(e):
            st.error("Email already exists")
        else:
            st.error("Username already exists")
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(USER_DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
              (username, hash_password(password)))
    user = c.fetchone()
    conn.close()
    return user

def insert_message(role, content):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO history (role, content) VALUES (?, ?)', (role, content))
    conn.commit()
    conn.close()

def fetch_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT role, content FROM history')
    rows = c.fetchall()
    conn.close()
    return rows

def clear_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM history')
    conn.commit()
    conn.close()

# Initialize the database
init_db()

def question(query):
    insert_message('user', query)
    history = fetch_history()
    ans = ""
    data = ol.chat(
        model='llama3',
        messages=[{'role': role, 'content': content} for role, content in history],
        stream=True 
    )

    for d in data:
        ans += d['message']['content']
    
    insert_message('assistant', ans)
    return ans

# App title
st.set_page_config(page_title="👨🏻 webcompanion-chat")
with st.sidebar:
    st.title("👨🏻 webcompanion-chat")

    # Display the conversation history in the sidebar
    st.write("Conversation History:")
    history = fetch_history()
    for role, content in history:
        display_role = "User" if role == 'user' else "Assistant"
        st.write(f"{display_role}: {content}")

    # Button to clear chat history
    st.sidebar.button('Clear Chat History', on_click=clear_history)

# User Authentication
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    mode = st.radio("Select Mode", ("Sign In", "Sign Up"))

    if mode == "Sign In":
        st.subheader("Sign In")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Sign In"):
            user = authenticate_user(username, password)
            if user:
                st.session_state.authenticated = True
                st.success("Login successful")
            else:
                st.error("Invalid username or password")

    elif mode == "Sign Up":
        st.subheader("Sign Up")
        email = st.text_input("Email")
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        if st.button("Sign Up"):
            create_user(email, new_username, new_password)
            st.success("Account created successfully")

else:
    st.subheader("Ask a Question")
    if prompt := st.chat_input("Your message"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

        # Generate a new response if the last message is not from the assistant
        if st.session_state.messages[-1]["role"] != "assistant":
            with st.chat_message("assistant"):
                response = question(prompt)
                placeholder = st.empty()
                full_response = ''
                for char in response:  # Assume response is a string
                    full_response += char
                    placeholder.markdown(full_response)
                    time.sleep(0.05)  # Adjust the delay as needed
            message = {"role": "assistant", "content": full_response}
            st.session_state.messages.append(message)
    
    # Add file uploader below the message input
    st.subheader("Upload a File")
    uploaded_file = st.file_uploader("Choose a file", type=["png", "jpg", "jpeg", "pdf", "txt", "webm", "mp4", "mkv"])
    if uploaded_file is not None:
        # Handle the uploaded file
        file_details = {"Filename": uploaded_file.name, "FileType": uploaded_file.type, "FileSize": uploaded_file.size}
        st.write(file_details)

        # Save the uploaded file to a designated directory
        save_path = os.path.join("uploads", uploaded_file.name)
        with open(save_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success(f"File saved to {save_path}")

    # Store LLM-generated responses
    if "messages" not in st.session_state.keys():
        st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]

    # Display or clear chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])
