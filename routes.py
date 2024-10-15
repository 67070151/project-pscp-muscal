from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from models import db, UserLogin, UserProfile, FoodItem, DailyFoodLog, FoodLogEntry
from datetime import date

app_bp = Blueprint('app_bp', __name__)

def validate_user_input(data, required_fields):
    """Validate required user input fields."""
    for field in required_fields:
        if field not in data or data[field] is None:
            return False, f"{field.replace('_', ' ').title()} is required."
    return True, None

@app_bp.route('/login', methods=['POST'])
def login():
    """Login endpoint for user authentication."""
    request_data = request.json
    username = request_data.get('username')
    password = request_data.get('password')

    user = UserLogin.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.user_id
        return jsonify({'message': 'Login successful!'}), 200

    return jsonify({'message': 'Invalid username or password.'}), 401

@app_bp.route('/register', methods=['POST'])
def register_user():
    """Registration endpoint for new users."""
    request_data = request.json
    username = request_data.get('username')
    password = request_data.get('password')

    # Validate input
    valid, error_message = validate_user_input(request_data, ['username', 'password'])
    if not valid:
        return jsonify({'error': error_message}), 400

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

@app_bp.route('/dashboard', methods=['GET'])
def dashboard():
    """Dashboard endpoint to retrieve user profile information."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    user_profile = UserProfile.query.filter_by(user_id=user_id).first()

    if user_profile:
        return jsonify({
            'user_id': user_profile.user_id,
            'calorie_goal': user_profile.calorie_goal,
            'protein_goal': user_profile.protein_goal,
            'carbohydrate_goal': user_profile.carbohydrate_goal,
            'fat_goal': user_profile.fat_goal
        }), 200

    return jsonify({'message': 'User profile not found.'}), 404

@app_bp.route('/add_food', methods=['POST'])
def add_food():
    """Endpoint to add a food item to the database."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    request_data = request.json
    food_name = request_data.get('food_name')
    serving_size = request_data.get('serving_size')
    servings_per_container = request_data.get('servings_per_container')
    calories_per_serving = request_data.get('calories_per_serving')

    # Get optional fields, allowing for 0 inputs
    carbohydrates_per_serving = request_data.get('carbohydrates_per_serving', 0)
    protein_per_serving = request_data.get('protein_per_serving', 0)
    fat_per_serving = request_data.get('fat_per_serving', 0)

    # Validate required fields
    valid, error_message = validate_user_input(request_data, ['food_name', 'serving_size', 'servings_per_container', 'calories_per_serving'])
    if not valid:
        return jsonify({'error': error_message}), 400

    # Convert to integers, ensuring they are numerical
    try:
        servings_per_container = int(servings_per_container)
        calories_per_serving = int(calories_per_serving)
        carbohydrates_per_serving = int(carbohydrates_per_serving)
        protein_per_serving = int(protein_per_serving)
        fat_per_serving = int(fat_per_serving)
    except ValueError:
        return jsonify({'error': 'All numeric fields must be valid numbers.'}), 400

    new_food = FoodItem(
        food_name=food_name,
        serving_size=serving_size,
        servings_per_container=servings_per_container,
        calories_per_serving=calories_per_serving,
        carbohydrates_per_serving=carbohydrates_per_serving,
        protein_per_serving=protein_per_serving,
        fat_per_serving=fat_per_serving
    )

    try:
        db.session.add(new_food)
        db.session.commit()
        return jsonify({'message': 'Food item added successfully.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app_bp.route('/log_food', methods=['POST'])
def log_food():
    """Endpoint to log food entries for a specific day."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    request_data = request.json
    log_date = request_data.get('log_date', date.today())
    food_id = request_data.get('food_id')
    quantity = request_data.get('quantity')

    # Validate input
    if not food_id or not quantity:
        return jsonify({'error': 'food_id and quantity are required.'}), 400

    # Find or create a daily food log
    daily_log = DailyFoodLog.query.filter_by(user_id=user_id, log_date=log_date).first()
    if not daily_log:
        daily_log = DailyFoodLog(user_id=user_id, log_date=log_date)
        db.session.add(daily_log)
        db.session.commit()

    # Log the food entry
    food_item = FoodItem.query.get(food_id)
    if not food_item:
        return jsonify({'error': 'Food item not found.'}), 404

    food_log_entry = FoodLogEntry(log_id=daily_log.log_id, food_id=food_item.food_id, quantity=quantity)
    db.session.add(food_log_entry)

    try:
        db.session.commit()
        return jsonify({'message': 'Food logged successfully.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app_bp.route('/view_log', methods=['GET'])
def view_log():
    """Endpoint to view food log for a specific day."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    log_date = request.args.get('log_date', date.today())

    daily_log = DailyFoodLog.query.filter_by(user_id=user_id, log_date=log_date).first()

    if not daily_log:
        return jsonify({'message': 'No log found for this date.'}), 404

    entries = []
    for entry in daily_log.food_entries:
        food_item = FoodItem.query.get(entry.food_id)
        entries.append({
            'food_name': food_item.food_name,
            'quantity': entry.quantity,
            'calories': food_item.calories_per_serving * entry.quantity
        })

    return jsonify({
        'date': log_date,
        'entries': entries
    }), 200
