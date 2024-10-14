from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask application and SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/muscal'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class UserLogin(db.Model):
    """Model for storing user login information."""
    __tablename__ = 'login_info'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # Establish relationship with UserProfile
    user_profile = db.relationship('UserProfile', backref='user_login', uselist=False)

class UserProfile(db.Model):
    """Model for storing user dietary goals and logs."""
    __tablename__ = 'user_info'

    user_id = db.Column(db.Integer, db.ForeignKey('login_info.user_id'), primary_key=True)
    calorie_goal = db.Column(db.Integer, default=2000, nullable=False)
    protein_goal = db.Column(db.Integer, default=25, nullable=False)
    carbohydrate_goal = db.Column(db.Integer, default=50, nullable=False)
    fat_goal = db.Column(db.Integer, default=25, nullable=False)
    food_log = db.Column(db.Text, nullable=True)

class FoodItem(db.Model):
    """Model for storing food information."""
    __tablename__ = 'foods'

    food_id = db.Column(db.Integer, primary_key=True)
    food_name = db.Column(db.String(100), nullable=False)
    serving_size = db.Column(db.String(50), nullable=False)
    servings_per_container = db.Column(db.Integer, nullable=False)
    calories_per_serving = db.Column(db.Integer, nullable=False)
    carbohydrates_per_serving = db.Column(db.Integer, nullable=False)
    protein_per_serving = db.Column(db.Integer, nullable=False)
    fat_per_serving = db.Column(db.Integer, nullable=False)

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint for user authentication."""
    request_data = request.json
    username = request_data.get('username')
    password = request_data.get('password')

    user = UserLogin.query.filter_by(username=username).first()

    if user:
        if check_password_hash(user.password_hash, password):
            return jsonify({'message': 'Login successful!'}), 200
        return jsonify({'message': 'Invalid password'}), 401

    return jsonify({'message': 'User not found'}), 404

@app.route('/register', methods=['POST'])
def register_user():
    """Registration endpoint for new users."""
    request_data = request.json
    username = request_data.get('username')
    password = request_data.get('password')

    # Validate input
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)

    new_user = UserLogin(username=username, password_hash=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()

        new_user_profile = UserProfile(user_id=new_user.user_id)
        db.session.add(new_user_profile)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username already exists.'}), 409
    except Exception as error:
        db.session.rollback()
        return jsonify({'error': str(error)}), 500

    return jsonify({'message': 'User registered successfully.'}), 201

@app.route('/dashboard/<int:user_id>', methods=['GET'])
def dashboard(user_id):
    """Dashboard endpoint to retrieve user profile information."""
    user_profile = UserProfile.query.filter_by(user_id=user_id).first()

    if user_profile:
        return jsonify({
            'user_id': user_profile.user_id,
            'calorie_goal': user_profile.calorie_goal,
            'protein_goal': user_profile.protein_goal,
            'carbohydrate_goal': user_profile.carbohydrate_goal,
            'fat_goal': user_profile.fat_goal,
            'food_log': user_profile.food_log
        }), 200

    return jsonify({'message': 'User profile not found.'}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
