import streamlit as st
import sqlite3
import os
import time
import ollama as ol

# Initialize the SQLite database
DB_PATH = 'chat_history.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            content TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

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

def create_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password))
    conn.commit()
    conn.close()

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
    user = c.fetchone()
    conn.close()
    return user

# Ensure the database is initialized
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

# User authentication
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "login_mode" not in st.session_state:
    st.session_state.login_mode = "Login"

def show_auth_page():
    st.subheader(st.session_state.login_mode)
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.session_state.login_mode == "Login":
        if st.button("Login"):
            user = authenticate_user(email, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.user = user
                st.success("Login successful")
            else:
                st.error("Invalid email or password")
        st.write("Don't have an account? [Create one](#)", unsafe_allow_html=True)
        if st.button("Create an Account"):
            st.session_state.login_mode = "Create Account"
    else:
        if st.button("Create Account"):
            try:
                create_user(email, password)
                st.success("Account created successfully")
                st.session_state.login_mode = "Login"
            except sqlite3.IntegrityError:
                st.error("Email already exists")
        st.write("Already have an account? [Login](#)", unsafe_allow_html=True)
        if st.button("Login"):
            st.session_state.login_mode = "Login"

if not st.session_state.logged_in:
    show_auth_page()
else:
    with st.sidebar:
        st.write("Conversation History:")
        history = fetch_history()
        for role, content in history:
            display_role = "User" if role == 'user' else "Assistant"
            st.write(f"{display_role}: {content}")

        # Button to clear chat history
        st.sidebar.button('Clear Chat History', on_click=clear_history)

    # Store LLM-generated responses
    if "messages" not in st.session_state.keys():
        st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]

    # Display or clear chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    # User-provided prompt
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
