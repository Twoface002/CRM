import os
import datetime
import logging
import atexit
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ✅ Initialize Extensions (but do not bind to app yet)
db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)
scheduler = BackgroundScheduler(executors={"default": ThreadPoolExecutor(max_workers=1)})

# ✅ Load environment variables
load_dotenv()

# ✅ Factory Function
def create_app():
    app = Flask(__name__)

    # ✅ Flask Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leads.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = True
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True

    # ✅ Initialize Extensions
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    CORS(app, supports_credentials=True)
    limiter.init_app(app)

    # ✅ Logging Configuration
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # ✅ Import Models *inside function* to avoid circular imports
    with app.app_context():
        from models import User, Followup, AccountOpen, Sale, Lead  # Ensure all models are imported
        db.create_all()  # ✅ Move this line inside the app context

    # ✅ Register Routes
    @app.route('/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'message': 'User already exists'}), 400

            new_user = User(
                email=data['email'],
                password=generate_password_hash(data['password']),
                role=data.get('role', 'staff'),
                name=data.get('name'),
                phone=data.get('phone'),
                dob=data.get('dob')
            )
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User registered successfully'}), 201

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            user = User.query.filter_by(email=data['email']).first()
            if user and check_password_hash(user.password, data['password']):
                access_token = create_access_token(identity={"email": user.email, "role": user.role})
                response = jsonify(access_token=access_token)
                response.set_cookie('access_token', access_token, httponly=True, secure=True, samesite='Lax')
                return response, 200

            return jsonify({'message': 'Invalid credentials'}), 401
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        response = jsonify({'message': 'Logout successful'})
        response.delete_cookie('access_token')
        return response, 200

    # ✅ Staff Endpoint
    @app.route('/staff', methods=['GET'])
    @jwt_required()
    def get_staff():
        try:
            current_user = get_jwt_identity()
            if current_user['role'] != 'admin':
                return jsonify({'message': 'Unauthorized'}), 403

            staff = User.query.all()
            return jsonify([{ "id": user.id, "email": user.email, "role": user.role, "last_active": user.last_active } for user in staff])
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/followup', methods=['GET'])
    @jwt_required()
    def get_followup():
        try:
            followups = Followup.query.all()
            return jsonify([followup.id for followup in followups])
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/account_open', methods=['GET'])
    @jwt_required()
    def get_account_open():
        try:
            accounts = AccountOpen.query.all()
            return jsonify([account.id for account in accounts])
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/sale', methods=['GET'])
    @jwt_required()
    def get_sale():
        try:
            sales = Sale.query.all()
            return jsonify([sale.id for sale in sales])
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/new_leads', methods=['GET'])
    @jwt_required()
    def get_new_leads():
        try:
            leads = Lead.query.all()
            return jsonify([lead.id for lead in leads])
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    # ✅ Inactivity Checker (Background Job)
    def check_inactivity():
        with app.app_context():  # ✅ Fix: Ensure app context
            try:
                from models import User
                now = datetime.datetime.utcnow()
                inactive_users = User.query.filter(
                    User.last_active.isnot(None),
                    User.last_active < now - datetime.timedelta(minutes=5)
                ).all()

                for user in inactive_users:
                    logging.warning(f"Alert: {user.email} is inactive for more than 5 minutes!")

                db.session.commit()
            except Exception as e:
                logging.error(f"Scheduler Error: {e}")

    # ✅ Add Scheduler Job
    with app.app_context():
        scheduler.add_job(check_inactivity, 'interval', minutes=1, replace_existing=True, misfire_grace_time=30)

    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))

    return app  # ✅ Return the Flask app

# ✅ Run the App
app = create_app()

if __name__ == '__main__':
    app.run(debug=False)
