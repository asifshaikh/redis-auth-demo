from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from config import Config
from models import db, User
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

    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200

@app.get('/profile')
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"id": user.id,"username": user.username}), 200

if __name__ == '__main__':
    app.run(debug=True)