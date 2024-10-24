from flask import request, jsonify, session
from app import app, db
from models import *
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from sqlalchemy.exc import IntegrityError
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def validate_user_input(data, required_fields):
    """Validate required user input fields."""
    for field in required_fields:
        if field not in data or data[field] is None:
            return False, f"{field.replace('_', ' ').title()} is required."
    return True, None


@app.route('/login', methods=['POST'])
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


@app.route('/register', methods=['POST'])
def register_user():
    """Registration endpoint for new users."""
    request_data = request.json
    username = request_data.get('username')
    password = request_data.get('password')

    valid, error_message = validate_user_input(request_data, ['username', 'password'])
    if not valid:
        return jsonify({'error': error_message}), 400

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


@app.route('/logout', methods=['POST'])
def logout():
    """Endpoint to log out the user."""
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully.'}), 200


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Retrieve user profile and daily progress for a specified date."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    log_date_str = request.args.get('log_date', None)
    if log_date_str:
        try:
            log_date = date.fromisoformat(log_date_str)
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    else:
        log_date = date.today()

    user_profile = UserProfile.query.filter_by(user_id=user_id).first()
    if not user_profile:
        return jsonify({'message': 'User profile not found.'}), 404

    daily_log = DailyFoodLog.query.filter_by(user_id=user_id, log_date=log_date).first()

    if daily_log:
        total_calories = daily_log.total_calories
        total_protein = daily_log.total_protein
        total_carbohydrates = daily_log.total_carbohydrates
        total_fat = daily_log.total_fat
    else:
        total_calories = total_protein = total_carbohydrates = total_fat = 0

    calorie_progress = (total_calories / user_profile.calorie_goal * 100) if user_profile.calorie_goal > 0 else 0
    protein_progress = (total_protein / user_profile.protein_goal * 100) if user_profile.protein_goal > 0 else 0
    carbohydrate_progress = (total_carbohydrates / user_profile.carbohydrate_goal * 100) if user_profile.carbohydrate_goal > 0 else 0
    fat_progress = (total_fat / user_profile.fat_goal * 100) if user_profile.fat_goal > 0 else 0

    return jsonify({
        'user_id': user_profile.user_id,
        'log_date': log_date.isoformat(),
        'calorie_goal': user_profile.calorie_goal,
        'protein_goal': user_profile.protein_goal,
        'carbohydrate_goal': user_profile.carbohydrate_goal,
        'fat_goal': user_profile.fat_goal,
        'total_calories': total_calories,
        'total_protein': total_protein,
        'total_carbohydrates': total_carbohydrates,
        'total_fat': total_fat,
        'calorie_progress': calorie_progress,
        'protein_progress': protein_progress,
        'carbohydrate_progress': carbohydrate_progress,
        'fat_progress': fat_progress
    }), 200

@app.route('/set_goal', methods=['POST'])
def set_goal():
    """Endpoint to set user dietary goals, ensuring protein, carb, and fat goals sum to 100 or less."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    request_data = request.json
    calorie_goal = request_data.get('calorie_goal')
    protein_goal = request_data.get('protein_goal')
    carbohydrate_goal = request_data.get('carbohydrate_goal')
    fat_goal = request_data.get('fat_goal')

    # Retrieve current profile data
    user_profile = UserProfile.query.filter_by(user_id=user_id).first()

    if not user_profile:
        return jsonify({'message': 'User profile not found.'}), 404

    # Set current values as defaults if not provided
    protein_goal = protein_goal if protein_goal is not None else user_profile.protein_goal
    carbohydrate_goal = carbohydrate_goal if carbohydrate_goal is not None else user_profile.carbohydrate_goal
    fat_goal = fat_goal if fat_goal is not None else user_profile.fat_goal

    # Check that the sum of protein, carbs, and fats does not exceed 100
    if protein_goal + carbohydrate_goal + fat_goal > 100:
        return jsonify({'error': 'Sum of protein, carbohydrate, and fat goals cannot exceed 100.'}), 400

    # Update goals if valid
    if calorie_goal:
        user_profile.calorie_goal = calorie_goal
    user_profile.protein_goal = protein_goal
    user_profile.carbohydrate_goal = carbohydrate_goal
    user_profile.fat_goal = fat_goal

    try:
        db.session.commit()
        return jsonify({'message': 'Goals updated successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/view_all_food', methods=['GET'])
def view_all_food():
    """Endpoint to view all food items."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    food_items = FoodItem.query.all()
    if not food_items:
        return jsonify({'message': 'No food items found.'}), 404

    food_list = []
    for item in food_items:
        food_list.append({
            'food_id': item.food_id,
            'food_name': item.food_name,
            'serving_size': item.serving_size,
            'servings_per_container': item.servings_per_container,
            'calories_per_serving': item.calories_per_serving,
            'carbohydrates_per_serving': item.carbohydrates_per_serving,
            'protein_per_serving': item.protein_per_serving,
            'fat_per_serving': item.fat_per_serving
        })

    return jsonify({'food_items': food_list}), 200

@app.route('/add_food', methods=['POST'])
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

@app.route('/delete_food', methods=['DELETE'])
def delete_food():
    """Endpoint to delete a food item, ensuring related food log entries are also deleted."""
    food_id = request.json.get('food_id')

    # Validate that the food_id is provided
    if not food_id:
        return jsonify({'error': 'food_id is required.'}), 400

    # Fetch the food item
    food_item = FoodItem.query.filter_by(food_id=food_id).first()

    if not food_item:
        return jsonify({'error': 'Food item not found.'}), 404

    try:
        # Begin transaction
        # Delete all related food log entries
        FoodLogEntry.query.filter_by(food_id=food_id).delete()

        # Now delete the food item
        db.session.delete(food_item)

        # Commit both deletions
        db.session.commit()
        return jsonify({'message': 'Food item and related log entries deleted successfully.'}), 200

    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/log_food', methods=['POST'])
def log_food():
    """Endpoint to log food entries for a specific day and update daily totals."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    request_data = request.json
    log_date = request_data.get('log_date', date.today())  # Default to today if no date provided
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

    # Fetch the food item details
    food_item = FoodItem.query.get(food_id)
    if not food_item:
        return jsonify({'error': 'Food item not found.'}), 404

    # Log the food entry
    food_log_entry = FoodLogEntry(log_id=daily_log.log_id, food_id=food_item.food_id, quantity=quantity)
    db.session.add(food_log_entry)

    # Update daily totals
    daily_log.total_calories += food_item.calories_per_serving * quantity
    daily_log.total_protein += food_item.protein_per_serving * quantity
    daily_log.total_carbohydrates += food_item.carbohydrates_per_serving * quantity
    daily_log.total_fat += food_item.fat_per_serving * quantity

    try:
        db.session.commit()
        return jsonify({'message': 'Food logged successfully and totals updated.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/view_log', methods=['GET'])
def view_log():
    """Endpoint to view food log and daily totals for a specific day."""
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    log_date = request.args.get('log_date', date.today())  # Default to today's date

    daily_log = DailyFoodLog.query.filter_by(user_id=user_id, log_date=log_date).first()

    if not daily_log:
        return jsonify({'message': 'No log found for this date.'}), 404

    # Retrieve entries for the day
    entries = []
    for entry in daily_log.food_entries:
        food_item = FoodItem.query.get(entry.food_id)
        entries.append({
            'food_name': food_item.food_name,
            'quantity': entry.quantity,
            'calories': food_item.calories_per_serving * entry.quantity,
            'protein': food_item.protein_per_serving * entry.quantity,
            'carbohydrates': food_item.carbohydrates_per_serving * entry.quantity,
            'fat': food_item.fat_per_serving * entry.quantity
        })

    return jsonify({
        'date': log_date,
        'total_calories': daily_log.total_calories,
        'total_protein': daily_log.total_protein,
        'total_carbohydrates': daily_log.total_carbohydrates,
        'total_fat': daily_log.total_fat,
        'entries': entries
    }), 200

@app.route('/delete_food_entry', methods=['DELETE'])
def delete_food_entry():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'message': 'User not logged in.'}), 401

    entry_id = request.json.get('entry_id')
    food_log_entry = FoodLogEntry.query.filter_by(entry_id=entry_id).first()
    
    if not food_log_entry:
        return jsonify({'error': 'Food log entry not found.'}), 404

    db.session.delete(food_log_entry)
    try:
        db.session.commit()
        return jsonify({'message': 'Food log entry deleted.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500