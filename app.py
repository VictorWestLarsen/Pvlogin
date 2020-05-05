import datetime
import base64

import uuid
from functools import wraps
import jwt
import requests
from flask_marshmallow import Marshmallow
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, String, Integer
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.http import parse_authorization_header
import os

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'planets.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
db = SQLAlchemy(app)
ma = Marshmallow(app)
db.__init__(app)


@app.cli.command('db_create')
def db_create():
    db.create_all()
    print('Database Created!')


@app.cli.command('db_drop')
def db_drop():
    db.drop_all()
    print('Database Dropped!')


@app.cli.command('db_seed')
def db_seed():
    feed_upcoming = Feed(feed_type="upcoming",
                 feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579394635.021413-human.mp4")
    feed_upcoming2 = Feed(feed_type="upcoming",
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/254/ellesgaard-254-1579326018.059277-human.mp4")
    feed_upcoming3 = Feed(feed_type="upcoming",
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/254/ellesgaard-254-1579429260.212495-human.mp4")
    feed_upcoming4 = Feed(feed_type="upcoming",
                         feed_url="https://storage.googleapis.com/porcovision-saved-videos/ellesgaard/256/ellesgaard-256-1579367213.956265-human.mp4")
    feed_ongoing = Feed(feed_type="ongoing",
                 feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579394169.802078-human.mp4")
    feed_ongoing2 = Feed(feed_type="ongoing",
                        feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579412110.43514-human.mp4")
    feed_ongoing3 = Feed(feed_type="ongoing",
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579420154.523119-human.mp4")
    feed_ongoing4 = Feed(feed_type="ongoing",
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579422374.868239-human.mp4")
    feed_completed = Feed(feed_type="completed",
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579429875.110848-human.mp4")
    feed_completed2 = Feed(feed_type="completed",
                          feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/248/ellesgaard-248-1579339595.370897-human.mp4")
    feed_completed3 = Feed(feed_type="completed",
                          feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/234/ellesgaard-234-1579359695.669374-human.mp4")
    feed_completed4 = Feed(feed_type="completed",
                          feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/254/ellesgaard-254-1579516496.906986-human.mp4")

    db.session.add(feed_upcoming)
    db.session.add(feed_upcoming2)
    db.session.add(feed_upcoming3)
    db.session.add(feed_upcoming4)
    db.session.add(feed_ongoing)
    db.session.add(feed_ongoing2)
    db.session.add(feed_ongoing3)
    db.session.add(feed_ongoing4)
    db.session.add(feed_completed)
    db.session.add(feed_completed2)
    db.session.add(feed_completed3)
    db.session.add(feed_completed4)

    test_user = User(first_name="Admin", last_name="DaBest", email="test@test.com", password="12345")
    db.session.add(test_user)
    db.session.commit()
    print("Database Seeded!")


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


@app.route('/feed', methods=["POST"])
def add_feed():
    data = request.get_json()
    new_feed = Feed(feed_type=data['feed_type'],feed_url=data['feed_url'])
    db.session.add(new_feed)
    db.session.commit()
    return jsonify({"message": "New feed added!"})


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    auth = request.headers.get('authorization')
    splitted = auth.split('Basic')
    user_encoded = splitted[1]
    user_decoded = base64.b64decode(user_encoded).decode('utf-8')
    user = user_decoded.split(":")
    email = user[0]
    password = user[1]

    user = User.query.filter_by(name=email).first()

    if not user:
        return make_response('Email or password is invalid!', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if check_password_hash(user.password, password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return make_response({'token': token.decode('UTF-8')})
    return make_response('Email or password is invalid!', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/feeds', methods=['GET'])
@cross_origin()
def get_feeds():
    upcoming_list = Feed.query.filter_by(feed_type="upcoming").all()
    ongoing_list = Feed.query.filter_by(feed_type="ongoing").all()
    completed_list = Feed.query.filter_by(feed_type="completed").all()
    result = [{"upcoming": feeds_schema.dump(upcoming_list), "ongoing": feeds_schema.dump(ongoing_list),
               "completed": feeds_schema.dump(completed_list)}]
    return jsonify(result)


# Db Models
class User(db.Model):
    _tablename_ = 'users'
    id = Column(Integer, primary_key=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True)
    password = Column(String)


class Feed(db.Model):
    __tablename__ = 'feeds'
    feed_id = Column(Integer, primary_key=True)
    feed_type = Column(String)
    feed_url = Column(String)


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'first_name', 'last_name', 'email', 'password')


class FeedSchema(ma.Schema):
    class Meta:
        fields = ('feed_id', 'feed_type', 'feed_url')


user_schema = UserSchema()
users_schema = UserSchema(many=True)

feed_schema = FeedSchema()
feeds_schema = FeedSchema(many=True)


if __name__ == '__main__':
    app.run()
