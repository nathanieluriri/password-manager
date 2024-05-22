import streamlit as st
from dotenv import load_dotenv

import pymongo
from pymodm.manager import Manager
from pymodm.queryset import QuerySet
import os
load_dotenv()
MONGO_URI= os.getenv("MONGO_URI")
st.set_page_config(page_title="Social Media Password Manager",page_icon="👻")
import bcrypt
from pymongo import MongoClient
from pymodm import connect, MongoModel, fields
from dotenv import load_dotenv
import os
load_dotenv()

MONGO_URI = os.getenv('MONGO_URI')
KEY= os.getenv('KEY')
connect(MONGO_URI)



from pymongo import MongoClient

# Connect to the MongoDB server
client = MongoClient(MONGO_URI)

# Select the database
db = client["passwordmanagerdb"]

# Select the collection
passwordsdb = db["passwords"]
def get_passwords_by_user(user_id):
    st.session_state.allOptions={}
    # Query for all passwords associated with the user
    result = passwordsdb.find({'user': user_id})


    # Convert the result to a list of dictionaries
    passwords_list = list(result)

    # Return the list of passwords
    return passwords_list












if "allOptions" not in st.session_state:
    st.session_state.allOptions={}



















from cryptography.fernet import Fernet



def encrypt_data(key, data):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    return encrypted_data

def decrypt_data(key, encrypted_data):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data







import re

def is_valid_email(email):
    # Regular expression pattern for validating email addresses
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    
    # Use re.match to check if the email matches the pattern
    if re.match(pattern, email):
        return True
    else:
        st.error("Invalid email address")
        return False
    

class User(MongoModel):
    user_name = fields.CharField(mongo_name="User Name")
    password = fields.CharField(mongo_name="Password")

class Passwords(MongoModel):
    user = fields.ReferenceField(User)
    password= fields.CharField(mongo_name="Password")
    tag= fields.CharField(mongo_name="Tag")
    social_media= fields.CharField(mongo_name="Social Media")




    

def signup(user, passw):
    hashed_passw = bcrypt.hashpw(passw.encode('utf-8'), bcrypt.gensalt())
    new_user = User(user_name=user, password=hashed_passw)
    new_user.save()
    return new_user

def login(user, passw):
    users = User.objects.all()

    for u in users:
        if user == u.user_name:
            checkP = u.password
            print("Loginnnnnnnnnn")
            checkP = checkP[2:-1]
            checkP = bytes(checkP, 'utf-8')
            if bcrypt.checkpw(passw.encode('utf-8'), checkP):
                return u

    return None

def start(process, user_name, password):
    if process == 1:
        return signup(user_name, password)
    elif process == 2:
        return login(user_name, password)
    else:
        raise ValueError("Invalid process")


def check_username_exists(username):
    users = User.objects.all()

    for u in users:
        if username == u.user_name:
            st.error("User exists")
            
            return True
    st.success("User doesn't exist")
    return False


def savepassword():
    new_password=st.session_state.new_password
    newestpassword=new_password.encode()
    encrypted_data=encrypt_data(key=KEY,data=newestpassword)
    
    password_doc = Passwords(user=st.session_state.user_logged._id, password=encrypted_data, tag=st.session_state.new_tag, social_media=st.session_state.social_password)
    

    password_doc.save()
    st.toast("Successfully saved Password 😁")

st.title("Social media password manager")
if "records" not in st.session_state: 
    st.session_state.records= None

if "user_logged" not in st.session_state:
    st.session_state.user_logged = False
if "wants" not in st.session_state:
    st.session_state.wants = "login"





def loginpage():
    # Get the MongoDB URI from the environment variable
    

    # Connect to the MongoDB database
    client = pymongo.MongoClient(MONGO_URI)

    # Display the login form
    username = st.text_input("Email address",key="name")
    password = st.text_input("Password", type="password",key="password")
    submit = st.button("Login")
    registerButton= st.button("Create an Account By Going to the Register Page",type="primary")
    if registerButton:
        st.session_state.wants="register"
        st.rerun()
    # Check if the form was submitted
    if submit:
        # Query the database for a user with the given username and password
        st.session_state.user_logged=start(2,st.session_state.name,st.session_state.password)

        # Check if a user was found
        if st.session_state.user_logged:
            # Display a success message
            st.success(f"Welcome {st.session_state.user_logged.user_name}")
            st.rerun()
        else:
            # Display an error message
            st.error("Invalid username or password")




def register():
    LoginButton= st.button("ALready have an account Login",type="primary")
    if LoginButton:
        st.session_state.wants="login"
        st.rerun()
    with st.form("register_form"):
        # Add text input fields for the user's name, email, and password
        email = st.text_input(" Enter Your Email Address ",key="name")
        password = st.text_input("Password", type="password",key="password")

        # Add a submit button
        submit = st.form_submit_button("Register")
        
    # Check if the form was submitted
        if submit:
            # Display a success message

            if(check_username_exists(st.session_state.name))==False and is_valid_email(st.session_state.name)==True:
                st.session_state.user_logged=start(1,st.session_state.name,st.session_state.password)
                st.success("User registered successfully")
                st.rerun()
                
            else:
                st.warning("Email already exists in DATABASE")
                
      






def mainui():
    
    passwords=get_passwords_by_user(st.session_state.user_logged._id)
    for password in passwords:
        st.session_state.allOptions.update({password['Tag']:{'Password': password['Password'],'Tag':password['Tag'],'Social Media':password['Social Media']}})

        
    

    viewPasswords,createPasswords= st.tabs(["View Previously Created Passwords","Create New Passwords"])
    with viewPasswords:
        
        st.selectbox("Which one of your Social media password do you want to see",options=["Twitter","Instagram","LinkedIn","Snapchat","Facebook","Pinterest","TikTok","Reddit","YouTube","Twitch","Tumblr","Quora"],index=None,key="socials")
        if st.session_state.socials:
            radio=[st.session_state.allOptions[account]["Tag"] for account, info in st.session_state.allOptions.items() if info["Social Media"] == st.session_state.socials]
            st.radio("Select a tag to see the password you wrote",options=radio,index=None,key="selected_password")# use tags to display the options
            
            if st.session_state.selected_password:
                selected_selected_password=st.session_state.allOptions[st.session_state.selected_password]['Password']
                pattern = r"b'|'$"
                result = re.sub(pattern, "", selected_selected_password)
                bt=result.encode()
                Dpassword=decrypt_data(KEY,bt)
                if st.button("Show Password 😋",type="primary"):
                    st.code(Dpassword.decode())
                    st.button("Hide Password 🤐",type="primary")
                
                    



    with createPasswords:

        st.text_input("Enter a tag",placeholder="Describe what the password should look like eg. (Bob's Instagram)",key="new_tag")
        st.text_input("Enter Your Password",type="password",key="new_password")
        st.selectbox("Which one of your Social media password do you want to save",options=["Twitter","Instagram","LinkedIn","Snapchat","Facebook","Pinterest","TikTok","Reddit","YouTube","Twitch","Tumblr","Quora"],index=None,key="social_password")
        if st.button("Save Password"):
            savepassword()






if st.session_state.user_logged == False:
    if st.session_state.wants== "login":
        loginpage()
    elif st.session_state.wants=="register":
        register()
else:
    mainui()

        

