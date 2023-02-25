from flask import Flask, jsonify, request
from bson.objectid import ObjectId
import pymongo
import re
import pyotp
import bcrypt

# flask call
app = Flask(__name__)

# connection to MongoDB
client =pymongo.MongoClient("mongodb://localhost:27017/")
db =client['AYUSH_Login']
collection =db['login']

# Validate the email address using a regex.
def is_email_address_valid(email):
    if not re.match("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$", email):
        return False
    return True

# send otp for authentication
def send_otp_for_authentication(id,_secret_key):
    login_user = collection.find({"_id":ObjectId(id)})
    totp = pyotp.TOTP(login_user[0]['secret key'])
    totp.now()
    return totp.verify(_secret_key)
    


@app.route('/login', methods=['POST'])
def login():
    _email = request.json['email']
    _password = request.json['password']
    _secret_key = request.json['secret key']
	# check for user exist or not
    if collection.count_documents({'email':_email})==0:
        return jsonify("User not exist")
    login_user = collection.find({"email":_email})
    if login_user[0]['email'] == _email:
        # password matching
        if bcrypt.hashpw(_password.encode('utf-8'), login_user[0]['password']) == login_user[0]['password']:
            correct = send_otp_for_authentication(login_user[0]['_id'],_secret_key)
            if correct:
                return jsonify("Login Successfull")
            else:
                return jsonify("Login Failed")
        else:
            return jsonify("Wrong Password")
    else:
        return jsonify("User does not exist")
            
# Main Function
if __name__ == "__main__":
    app.run(debug = True)