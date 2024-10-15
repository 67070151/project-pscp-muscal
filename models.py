from flask_sqlalchemy import SQLAlchemy
from datetime import date

db = SQLAlchemy()

class UserLogin(db.Model):
    """Model for storing user login information."""
    __tablename__ = 'login_info'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    user_profile = db.relationship('UserProfile', backref='user_login', uselist=False)

class UserProfile(db.Model):
    """Model for storing user dietary goals and logs."""
    __tablename__ = 'user_info'

    user_id = db.Column(db.Integer, db.ForeignKey('login_info.user_id'), primary_key=True)
    calorie_goal = db.Column(db.Integer, default=2000, nullable=False)
    protein_goal = db.Column(db.Integer, default=25, nullable=False)
    carbohydrate_goal = db.Column(db.Integer, default=50, nullable=False)
    fat_goal = db.Column(db.Integer, default=25, nullable=False)

    daily_food_logs = db.relationship('DailyFoodLog', backref='user_profile', lazy=True)

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

class DailyFoodLog(db.Model):
    """Model for storing daily food logs."""
    __tablename__ = 'daily_food_logs'
    
    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_info.user_id'), nullable=False)
    log_date = db.Column(db.Date, default=date.today, nullable=False)

    food_entries = db.relationship('FoodLogEntry', backref='daily_food_log', lazy=True)

class FoodLogEntry(db.Model):
    """Model for storing entries in a daily food log."""
    __tablename__ = 'food_log_entries'
    
    entry_id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey('daily_food_logs.log_id'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('foods.food_id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
