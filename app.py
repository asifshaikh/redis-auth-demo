from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from config import Config
from models import db, User
from redis_client import redis_client
import bcrypt

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    
    return {"message": "Redis auth project"}

@app.post('/signup')
def signup():
    data = request.get_json()
    if not data:
            return jsonify({"error": "Request body is required"}), 400
    
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400
    
    hashed_password = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()

    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201

@app.post('/login')
def login():
    data = request.get_json()

    if not data:
          return jsonify({"error": "Request body is required"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
         return jsonify({"error": "User not found"}), 404

    password_valid = bcrypt.checkpw(password.encode(), user.password.encode())
    if not password_valid:
        return jsonify({"error": "Invalid password"}), 401

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    # store access and refresh token in redis
    redis_client.setex(f"access_token:{user.id}",900,access_token)
    redis_client.setex(f"refresh_token:{user.id}", 604800, refresh_token)

    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200

@app.get('/profile')
@jwt_required()
def profile():
    user_id = get_jwt_identity()

    access_token = request.headers.get('Authorization').split(" ")[1]

    stored_token = redis_client.get(f"access_token:{user_id}")

    if access_token != stored_token:
        return jsonify({"error": "Session expired or revoked"}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"id": user.id,"username": user.username}), 200

@app.post('/refresh')
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify({"access_token": access_token}), 200

@app.post('/logout')
@jwt_required()
def logout():
    user_id = get_jwt_identity()

    redis_client.delete(f"access_token:{user_id}")
    redis_client.delete(f"refresh_token:{user_id}")

    return jsonify({"message": "Logout successful"}), 200

@app.get('/redis-test')
def redis_test():
    redis_client.set("test_key", "test_value")
    value = redis_client.get("test_key")
    return {"message": value}

if __name__ == '__main__':
    app.run(debug=True)