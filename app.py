import datetime
import uuid
from functools import wraps
import enum
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)

db = SQLAlchemy(app)
db.__init__(app)


class FeedStatus(enum.Enum):
    upcoming = 1
    ongoing = 2
    completed = 3


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Text)
    name = db.Column(db.String(80))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Feed(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(Enum(FeedStatus))
    url = db.Column(db.Text)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()

    output = []
    for user in users:
        user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"Message": "No user found with that ID"})

    user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, 'admin': user.admin}

    return jsonify({"user": user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "new user created!"})


@app.route('/video')
def add_url():
    data = request.get_json()
    new_feed = Feed(ongoing=data['ongoing'], completed=data['completed'], upcoming=data['upcoming'], url=data['url'])
    db.session.add(new_feed)
    db.session.commit()
    return jsonify({"message": "New feed added"})


@app.route('/user/promote/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"Message": "No user found with that ID"})
    if user.admin:
        return jsonify({"Message": "User is already admin!"})
    elif not user.admin:
        user.admin = True
        db.session.commit()
        return jsonify({"Message": "User has been promoted!"})


@app.route('/user/demote/<public_id>', methods=['PUT'])
@token_required
def demote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"Message": "No user found with that ID"})

    if user.admin:
        user.admin = False
        db.session.commit()
        return jsonify({"Message": "User has been demoted!"})

    elif not user.admin:
        return jsonify({"Message": "User is not admin!"})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"Message": "No user found with that ID"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'Message': 'The user has been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})



if __name__ == '__main__':
    app.run()
