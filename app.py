from flask import Flask
from models import db
from config import Config
from routes import app_bp

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

@app.route('/')
def home():
    return "Welcome to the Food Tracker API!"

app.register_blueprint(app_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    app.run(debug=True)
