import base64
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, set_access_cookies, \
    set_refresh_cookies, unset_jwt_cookies, jwt_required, jwt_refresh_token_required, current_user, get_jwt_identity
from functools import wraps
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'Porco.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.urandom(32)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
CORS(app, origins=['http://localhost:4200'])
app.config['CORS_HEADERS'] = 'Content-Type'
jwt = JWTManager(app)
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
    feed_upcoming = Feed(feed_type="upcoming", box_number=5,
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579394635.021413-human.mp4")
    feed_upcoming2 = Feed(feed_type="upcoming", box_number=6,
                          feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/254/ellesgaard-254-1579326018.059277-human.mp4")
    feed_upcoming3 = Feed(feed_type="upcoming", box_number=7,
                          feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/254/ellesgaard-254-1579429260.212495-human.mp4")
    feed_upcoming4 = Feed(feed_type="upcoming", box_number=15,
                          feed_url="https://storage.googleapis.com/porcovision-saved-videos/ellesgaard/256/ellesgaard-256-1579367213.956265-human.mp4")
    feed_ongoing = Feed(feed_type="ongoing", box_number=8,
                        feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579394169.802078-human.mp4")
    feed_ongoing2 = Feed(feed_type="ongoing", box_number=9,
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579412110.43514-human.mp4")
    feed_ongoing3 = Feed(feed_type="ongoing", box_number=10,
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579420154.523119-human.mp4")
    feed_ongoing4 = Feed(feed_type="ongoing", box_number=11,
                         feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579422374.868239-human.mp4")
    feed_completed = Feed(feed_type="completed", box_number=2,
                          feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/231/ellesgaard-231-1579429875.110848-human.mp4")
    feed_completed2 = Feed(feed_type="completed", box_number=3,
                           feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/248/ellesgaard-248-1579339595.370897-human.mp4")
    feed_completed3 = Feed(feed_type="completed", box_number=4,
                           feed_url="https://storage.googleapis.com/porcovision-minidecoder/ellesgaard/234/ellesgaard-234-1579359695.669374-human.mp4")
    feed_completed4 = Feed(feed_type="completed", box_number=12,
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


@app.route('/api/add_feed', methods=["POST"])
def add_feed():
    data = request.get_json()
    new_feed = Feed(feed_type=data['feed_type'], feed_url=data['feed_url'], box_number=data['box_number'])
    db.session.add(new_feed)
    db.session.commit()
    return jsonify({"message": "New feed added!"})


@app.route('/api/login', methods=['POST'])
@cross_origin(headers=['Content-Type', 'Authorization'])
def login():
    auth = request.headers.get('authorization')
    splitter = auth.split('Basic')
    user_encoded = splitter[1]
    user_decoded = base64.b64decode(user_encoded).decode('utf-8')
    user = user_decoded.split(":")
    email = user[0]
    password = user[1]

    user = User.query.filter_by(email=email).first()

    if not user:
        return make_response('Email or password is invalid!', 401,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if user.password == password:
        # Create Access and refresh token, based on the users email.
        access_token = create_access_token(identity=email)
        refresh_token = create_refresh_token(identity=email)
        resp = jsonify({'login': True})
        # Set JWT cookies in response
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp, 200
    return make_response('Email or password is invalid!', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/api/feeds', methods=['GET'])
@cross_origin()
@jwt_required
def get_feeds():
    upcoming_list = Feed.query.filter_by(feed_type="upcoming").all()
    ongoing_list = Feed.query.filter_by(feed_type="ongoing").all()
    completed_list = Feed.query.filter_by(feed_type="completed").all()
    result = [{"upcoming": feeds_schema.dump(upcoming_list), "ongoing": feeds_schema.dump(ongoing_list),
               "completed": feeds_schema.dump(completed_list)}]
    return jsonify(result)


@app.route('/api/logout', methods=['POST'])
def logout():
    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    return resp, 200


@app.route('/api/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    return resp, 200


@app.route('/api/update_type', methods=['PUT'])
def update_type():
    data = request.get_json()
    update = Feed.query.filter_by(box_number=data['box_number']).first()
    update.feed_type = data['feed_type']
    db.session.commit()
    return jsonify(message="feed type updated"), 200


@app.route('/api/remove_feed/<int:box_number>', methods=['DELETE'])
def remove_feed(box_number:int):
    Feed.query.filter_by(box_number=box_number).delete()
    db.session.commit()
    return jsonify(message="Feed with box number " + str(box_number) + " was deleted")



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
    box_number = Column(Integer)


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'first_name', 'last_name', 'email', 'password')


class FeedSchema(ma.Schema):
    class Meta:
        fields = ('box_number', 'feed_type', 'feed_url')


user_schema = UserSchema()
users_schema = UserSchema(many=True)

feed_schema = FeedSchema()
feeds_schema = FeedSchema(many=True, only=("feed_url", "box_number"))

if __name__ == '__main__':
    app.run()
