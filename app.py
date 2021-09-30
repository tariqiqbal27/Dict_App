from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from six import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


# __________ START OF MODEL ________________
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50),nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Dictionary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    word = db.Column(db.String(30),nullable=False)
    definition = db.Column(db.String(100),nullable=False)


# ___________ END OF MODELS ______________

# Decorator for login required
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # JWT is passed in the request header
        if 'bearer' in request.headers:
            token = request.headers['bearer']

        # Return 401 if token is not provided
        if not token:
            return jsonify({'message': 'Token is missing!!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({
                'message': 'Token is invalid!!'
            }), 401
        # returns the current logged in users context to the routes
        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/login", methods=['POST'])
def login():
    auth = request.form
    # return 401 if email/password missing
    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response('Please enter email/Password', 401)
    user = User.query.filter_by(email=auth.get('email')).first()
    if not user:
        # return 401 if user not exists
        return make_response('Could not verify', 401)

    if check_password_hash(user.password, auth.get('password')):
        # Creating JWT Token
        token = jwt.encode({
            'id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=5)  # valid for 5 hours
        }, app.config['SECRET_KEY'])
        return make_response(jsonify({'token': token}), 201)
        # return 403 if password is wrong
    return jsonify({'message': 'wrong email/password'}), 403


@app.route("/signup", methods=['POST'])
def signup():
    data = request.form
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Please fill all the required fields'}), 400
    email, password = data.get('email'), data.get('password')
    # Checking if user already exists or not
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            email=email,
            password=generate_password_hash(password)
        )
        # Insert user into Database
        db.session.add(user)
        db.session.commit()
        return make_response('Account Created Successfully', 201)
    else:
        return make_response('User already exists', 202)


# Getting data of current signed user
@app.route("/user", methods=['GET'])
@token_required
def get_user(current_user):
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'admin_status': current_user.is_admin
    })


# For Searching Word
@app.route("/search/<word>")
@token_required
def search_definition(current_user, word):
    # Searching for word in Dictionary
    dictionary = Dictionary.query.filter_by(word=word).first()
    # If word is not found in dictionary
    if not dictionary:
        return jsonify({'message': 'No such word found.'}), 202

    dictionary = Dictionary.query.filter_by(word=word)
    output = []
    for d in dictionary:
        output.append({
            'definition': d.definition
        })
    return jsonify({"result": output}), 202


# For adding new word in dictionary
@app.route("/add", methods=['POST'])
@token_required
def add_word(current_user):
    # Checking if current user is Admin or not
    if current_user.is_admin is False:
        return jsonify({'message': 'Not authorized to perform this task'}), 401
    data = request.form
    if not data or not data.get('word') or not data.get('definition'):
        return make_response('Please enter word/definition', 400)
    word, definition = data.get('word'), data.get('definition')
    # Checking if same word and definition already existed in DB
    exist_word = Dictionary.query.filter_by(word=word, definition=definition).first()
    if exist_word:
        return jsonify({"message": "Word already exist", }), 202
    # inserting new word into Database
    dict_data = Dictionary(word=word, definition=definition)
    db.session.add(dict_data)
    db.session.commit()
    return jsonify({'message': 'Word added Successfully'}), 201


# for removing word from dictionary
@app.route("/remove", methods=['POST'])
@token_required
def delete_word(current_user):
    # Checking if current logged in user is Admin or not
    if current_user.is_admin is False:
        return jsonify({'message': 'Not authorized to perform this task'}), 401
    data = request.form
    # Checking if all parameter are passed
    if not data or not data.get('word'):
        return make_response('missing parameter', 400)
    word = data.get('word')
    # Checking if word already existed
    exist_word = Dictionary.query.filter_by(word=word).first()
    if not exist_word:
        return jsonify({"message": "Word not exist", }), 202
    all_word = Dictionary.query.filter_by(word=word)
    # Deleting word from database
    db.session.delete(all_word)
    db.session.commit()
    return jsonify({'message': "Word deleted Successfully"}), 202


@app.route("/promote", methods=['POST'])
@token_required
def make_admin(current_user):
    if current_user.is_admin is False:
        return jsonify({'message': "Not authorized to perform this task"}), 401
    data = request.form
    # Checking if all parameter are passed
    if not data or not data.get('email'):
        return jsonify({'message': 'Email missing!!!'}), 400
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    # Checking if user exists
    if not user:
        return jsonify({'message': "User does not exist!!!"}), 202
    if user.is_admin is True:
        return jsonify({'message': 'User is already Admin'}), 202
    user.is_admin = True
    db.session.commit()
    return jsonify({'message': 'User successfully promoted to Admin'}), 202


if __name__ == "__main__":
    app.run(debug=True)
