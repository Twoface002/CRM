import os
import datetime
import logging
import atexit
import io
from flask import Flask, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt, get_current_user
from extensions import db, jwt, migrate, limiter, scheduler
import pandas as pd
from facebook_business.api import FacebookAdsApi
from facebook_business.adobjects.leadgenform import LeadgenForm
from facebook_business.adobjects.page import Page
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import random
import string
from sqlalchemy import func

# Load environment variables
load_dotenv()

# Initialize Flask-Mail
mail = Mail()

# Factory Function
def create_app():
    app = Flask(__name__)

    # Flask Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leads.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'

    # Mail Configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

    # Initialize Mail
    mail.init_app(app)

    # Configure upload folder
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'csv'}
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    # Initialize Extensions
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    
    # Configure CORS - simplified for development
    CORS(app, 
         resources={r"/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:5000", "http://localhost:5000"]}},
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization", "Accept", "Origin"],
         expose_headers=["Content-Type", "Authorization"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         max_age=3600)
    
    limiter.init_app(app)

    # Logging Configuration
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.filter_by(email=identity).first()

    @jwt.user_identity_loader
    def user_identity_lookup(user):
        if isinstance(user, str):
            return user
        return user.email

    logger.info("Initializing database...")
    with app.app_context():
        # Import all models
        from models import User, Followup, AccountOpen, Sale, Lead
        
        # Create tables only if they don't exist
        logger.info("Creating database tables if they don't exist...")
        db.create_all()
        
        # Create initial admin user only if no users exist
        if not User.query.first():
            admin_user = User(
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin',
                name='Admin User',
                is_active=True,
                cursor_x=0,
                cursor_y=0,
                last_cursor_move=datetime.datetime.utcnow()
            )
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Created initial admin user (email: admin@example.com, password: admin123)")
            
        logger.info("Database initialization complete.")

    # Register Routes
    @app.route('/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'message': 'User already exists'}), 400

            # Convert date string to Python date object
            dob = datetime.datetime.strptime(data['dob'], '%Y-%m-%d').date() if data.get('dob') else None

            new_user = User(
                email=data['email'],
                password=generate_password_hash(data['password']),
                role=data.get('role', 'staff'),
                name=data.get('name'),
                phone=data.get('phone'),
                dob=dob
            )
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User registered successfully'}), 201

        except ValueError as e:
            db.session.rollback()
            logger.error(f"Date format error: {e}")
            return jsonify({'message': 'Invalid date format. Please use YYYY-MM-DD'}), 400
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/login', methods=['POST', 'OPTIONS'])
    def login():
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        try:
            data = request.get_json()
            if not data or 'email' not in data or 'password' not in data:
                return jsonify({'message': 'Missing email or password'}), 400

            user = User.query.filter_by(email=data['email']).first()
            if not user:
                return jsonify({'message': 'Invalid email or password'}), 401

            if not check_password_hash(user.password, data['password']):
                return jsonify({'message': 'Invalid email or password'}), 401

            # Update last active time
            user.last_active = datetime.datetime.utcnow()
            db.session.commit()
            
            # Create access token with user object
            access_token = create_access_token(identity=user)
            
            response = jsonify({
                'access_token': access_token,
                'role': user.role,
                'email': user.email,
                'name': user.name,
                'id': user.id
            })
            
            # Add CORS headers
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            
            return response, 200

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return jsonify({'message': 'An error occurred during login'}), 500

    @app.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        response = jsonify({'message': 'Logout successful'})
        response.delete_cookie('access_token')
        return response, 200

    @app.route('/profile', methods=['GET', 'OPTIONS'])
    @jwt_required()
    def get_profile():
        # Handle OPTIONS request first
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'message': 'User not found'}), 404
            response = jsonify({
                'email': current_user.email,
                'name': current_user.name,
                'role': current_user.role,
                'phone': current_user.phone,
                'dob': current_user.dob.strftime('%Y-%m-%d') if current_user.dob and isinstance(current_user.dob, (datetime.date, datetime.datetime)) else current_user.dob
            })
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response, 200
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/profile/update', methods=['PUT', 'OPTIONS'])
    @jwt_required()
    def update_profile():
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Methods', 'PUT')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            return response

        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'message': 'User not found'}), 404

            data = request.get_json()
            
            # Update user fields
            if 'name' in data:
                current_user.name = data['name']
            if 'phone' in data:
                current_user.phone = data['phone']
            if 'dob' in data and data['dob']:
                try:
                    # Handle both date string and None cases
                    if data['dob'] == '' or data['dob'] is None:
                        current_user.dob = None
                    else:
                        current_user.dob = datetime.datetime.strptime(data['dob'], '%Y-%m-%d').date()
                except ValueError as e:
                    logger.error(f"Date parsing error: {e}")
                    return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400

            # Email can only be updated by admin
            if 'email' in data and current_user.email != data['email']:
                if current_user.role != 'admin':
                    return jsonify({'message': 'Email can only be updated by admin'}), 403
                if User.query.filter_by(email=data['email']).first():
                    return jsonify({'message': 'Email already exists'}), 400
                current_user.email = data['email']

            db.session.commit()
            
            return jsonify({
                'message': 'Profile updated successfully',
                'user': {
                    'name': current_user.name,
                    'email': current_user.email,
                    'phone': current_user.phone,
                    'dob': current_user.dob.strftime('%Y-%m-%d') if current_user.dob and isinstance(current_user.dob, (datetime.date, datetime.datetime)) else None
                }
            }), 200

        except Exception as e:
            logger.error(f"Error in update_profile: {str(e)}")
            db.session.rollback()
            return jsonify({'message': 'An error occurred while updating profile'}), 500

    @app.route('/staff', methods=['GET', 'OPTIONS'])
    @jwt_required()
    def get_staff():
        # Handle OPTIONS request first
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        try:
            current_user = get_current_user()
            if current_user.role != 'admin':
                return jsonify({'message': 'Unauthorized'}), 403

            staff = User.query.all()
            response = jsonify([{
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "name": user.name,
                "last_active": user.last_active.isoformat() if user.last_active else None
            } for user in staff])
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response, 200
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

    @app.route('/staff/<int:staff_id>', methods=['GET', 'DELETE'])
    @jwt_required()
    def handle_staff(staff_id):
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            if current_user.role != 'admin':
                return jsonify({'error': 'Unauthorized'}), 403

            # Find the staff member
            staff = User.query.get(staff_id)
            if not staff:
                return jsonify({'error': 'Staff member not found'}), 404

            if request.method == 'DELETE':
                # Prevent deleting the last admin
                if staff.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
                    return jsonify({'error': 'Cannot delete the last admin user'}), 400

                db.session.delete(staff)
                db.session.commit()
                return jsonify({'message': 'Staff member deleted successfully'}), 200
            else:  # GET method
                # Get staff's leads and stats
                leads = Lead.query.filter_by(assigned_staff_id=staff.id).all()
                total_leads = len(leads)
                contacted_leads = sum(1 for lead in leads if lead.status == 'contacted')
                converted_leads = sum(1 for lead in leads if lead.status == 'converted')

                return jsonify({
                    'id': staff.id,
                    'email': staff.email,
                    'name': staff.name,
                    'phone': staff.phone,
                    'role': staff.role,
                    'last_active': staff.last_active.isoformat() if staff.last_active else None,
                    'total_leads': total_leads,
                    'contacted_leads': contacted_leads,
                    'converted_leads': converted_leads
                }), 200

        except Exception as e:
            logger.error(f"Error in handle_staff: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/staff/<email>', methods=['GET'])
    @jwt_required()
    def get_staff_details(email):
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            # Find the staff member
            staff = User.query.filter_by(email=email).first()
            if not staff:
                return jsonify({'error': 'Staff member not found'}), 404

            # Get staff's leads and stats
            leads = Lead.query.filter_by(assigned_staff_id=staff.id).order_by(Lead.created_at.desc()).all()
            total_leads = len(leads)
            new_leads = sum(1 for lead in leads if lead.status == 'new')
            contacted_leads = sum(1 for lead in leads if lead.status == 'contacted')
            converted_leads = sum(1 for lead in leads if lead.status == 'converted')

            # Get staff's recent activity
            recent_followups = Followup.query.filter_by(staff_id=staff.id).order_by(Followup.followup_date.desc()).limit(5).all()
            recent_sales = Sale.query.filter_by(staff_id=staff.id).order_by(Sale.sale_date.desc()).limit(5).all()

            return jsonify({
                'staff_details': {
                    'id': staff.id,
                    'email': staff.email,
                    'name': staff.name,
                    'role': staff.role,
                    'phone': staff.phone,
                    'last_active': staff.last_active.isoformat() if staff.last_active else None
                },
                'stats': {
                    'total_leads': total_leads,
                    'new_leads': new_leads,
                    'contacted_leads': contacted_leads,
                    'converted_leads': converted_leads
                },
                'recent_activity': {
                    'followups': [{
                        'id': f.id,
                        'lead_id': f.lead_id,
                        'date': f.followup_date.isoformat(),
                        'notes': f.notes
                    } for f in recent_followups],
                    'sales': [{
                        'id': s.id,
                        'lead_id': s.lead_id,
                        'date': s.sale_date.isoformat(),
                        'amount': s.amount
                    } for s in recent_sales]
                }
            }), 200

        except Exception as e:
            logger.error(f"Error in get_staff_details: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/staff/<int:staff_id>/leads', methods=['GET'])
    @jwt_required()
    def get_staff_leads(staff_id):
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            # Only allow admin or the staff member themselves to view their leads
            if current_user.role != 'admin' and current_user.id != staff_id:
                return jsonify({'error': 'Unauthorized'}), 403

            # Get staff member
            staff = User.query.get(staff_id)
            if not staff:
                return jsonify({'error': 'Staff member not found'}), 404

            # Get leads with optional filters
            query = Lead.query.filter_by(assigned_staff_id=staff_id)
            
            # Apply filters if provided
            status = request.args.get('status')
            if status:
                query = query.filter_by(status=status)

            # Apply date range filter if provided
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            if start_date and end_date:
                query = query.filter(
                    Lead.created_at >= datetime.datetime.fromisoformat(start_date),
                    Lead.created_at <= datetime.datetime.fromisoformat(end_date)
                )

            # Order by created_at desc
            leads = query.order_by(Lead.created_at.desc()).all()

            lead_list = [{
                'id': lead.id,
                'name': lead.name,
                'email': lead.email,
                'phone': lead.phone,
                'city': lead.city,
                'source': lead.source,
                'status': lead.status,
                'created_at': lead.created_at.isoformat() if lead.created_at else None
            } for lead in leads]

            return jsonify({
                'staff_id': staff_id,
                'staff_name': staff.name,
                'leads': lead_list,
                'total_count': len(lead_list)
            }), 200

        except Exception as e:
            logger.error(f"Error in get_staff_leads: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/staff/<int:staff_id>/update_lead/<int:lead_id>', methods=['PUT'])
    @jwt_required()
    def update_staff_lead(staff_id, lead_id):
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            # Only allow admin or the assigned staff member to update the lead
            if current_user.role != 'admin' and current_user.id != staff_id:
                return jsonify({'error': 'Unauthorized'}), 403

            # Get the lead
            lead = Lead.query.get(lead_id)
            if not lead:
                return jsonify({'error': 'Lead not found'}), 404

            # Verify lead belongs to staff
            if lead.assigned_staff_id != staff_id:
                return jsonify({'error': 'Lead not assigned to this staff member'}), 403

            # Update lead data
            data = request.get_json()
            if 'status' in data:
                lead.status = data['status']
            if 'notes' in data:
                # Create a new followup
                followup = Followup(
                    lead_id=lead_id,
                    staff_id=staff_id,
                    followup_date=datetime.datetime.utcnow(),
                    notes=data['notes']
                )
                db.session.add(followup)

            db.session.commit()
            return jsonify({'message': 'Lead updated successfully'}), 200

        except Exception as e:
            logger.error(f"Error in update_staff_lead: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/upload_leads', methods=['POST'])
    @jwt_required()
    def upload_leads():
        try:
            current_user = get_current_user()
            if not current_user:
                logger.error("No authenticated user found")
                return jsonify({'error': 'Authentication required'}), 401

            logger.info(f"Upload leads initiated by user: {current_user.email} (role: {current_user.role}, id: {current_user.id})")

            if 'file' not in request.files:
                logger.error('No file part in request')
                return jsonify({'error': 'No file part'}), 400
            
            file = request.files['file']
            if file.filename == '':
                logger.error('No selected file')
                return jsonify({'error': 'No selected file'}), 400
            
            if not file.filename.endswith('.csv'):
                logger.error(f'Invalid file type: {file.filename}')
                return jsonify({'error': 'Invalid file type. Only CSV files are allowed'}), 400

            # Create uploads directory if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # Read CSV file
                df = pd.read_csv(filepath)
                logger.info(f'CSV columns: {df.columns.tolist()}')
                
                # Map CSV columns to database columns
                column_mapping = {
                    'Name': 'name',
                    'Mail-id': 'email',
                    'Number': 'phone',
                    'City': 'city'
                }
                
                # Rename columns according to mapping
                df = df.rename(columns=column_mapping)
                logger.info(f'Columns after mapping: {df.columns.tolist()}')
                
                required_columns = ['name', 'email', 'phone', 'city']
                missing_columns = [col for col in required_columns if col not in df.columns]
                
                if missing_columns:
                    logger.error(f'Missing required columns: {missing_columns}')
                    return jsonify({
                        'error': 'Invalid CSV structure',
                        'missing_columns': missing_columns,
                        'required_columns': required_columns
                    }), 400
                
                # Get all active staff members for assignment
                staff_members = User.query.filter_by(role='staff', is_active=True).all()
                if not staff_members:
                    logger.error('No active staff members found for lead assignment')
                    return jsonify({'error': 'No active staff members found'}), 400
                
                # Process leads
                count = 0
                assigned_count = 0
                for _, row in df.iterrows():
                    try:
                        # Create new lead with all fields
                        lead = Lead(
                            name=str(row['name']).strip(),
                            email=str(row['email']).strip(),
                            phone=str(row['phone']).strip(),
                            source='csv_import',
                            status='new',
                            city=str(row['city']).strip() if 'city' in row else None
                        )
                        
                        # Assign to staff member with least leads
                        if staff_members:
                            # Get staff member with least leads
                            staff_with_counts = []
                            for staff in staff_members:
                                lead_count = Lead.query.filter_by(assigned_staff_id=staff.id).count()
                                staff_with_counts.append((staff, lead_count))
                            
                            # Sort by lead count and get the staff member with least leads
                            staff_with_counts.sort(key=lambda x: x[1])
                            assigned_staff = staff_with_counts[0][0]
                            
                            # Assign the lead
                            lead.assigned_staff_id = assigned_staff.id
                            assigned_count += 1
                            logger.info(f"Assigned lead {lead.name} to staff member {assigned_staff.name}")
                        
                        db.session.add(lead)
                        count += 1
                        
                        # Commit every 100 leads to avoid memory issues
                        if count % 100 == 0:
                            db.session.commit()
                            logger.info(f'Committed batch of {count} leads ({assigned_count} assigned)')
                            
                    except Exception as e:
                        logger.error(f'Error processing row: {row}, Error: {str(e)}')
                        continue
                
                # Final commit for remaining leads
                db.session.commit()
                logger.info(f'Successfully imported {count} leads (Total assigned: {assigned_count})')
                
                # Clean up
                os.remove(filepath)
                
                return jsonify({
                    'message': 'Leads imported successfully',
                    'count': count,
                    'assigned_count': assigned_count
                }), 200
                
            except Exception as e:
                logger.error(f'Error processing CSV: {str(e)}')
                if os.path.exists(filepath):
                    os.remove(filepath)
                return jsonify({
                    'error': 'Error processing CSV file',
                    'details': str(e)
                }), 500
            
        except Exception as e:
            logger.error(f'Unexpected error in upload_leads: {str(e)}')
            return jsonify({
                'error': 'An unexpected error occurred',
                'details': str(e)
            }), 500

    @app.route('/connect_meta', methods=['GET'])
    @jwt_required()
    def connect_meta():
        try:
            # Get Meta API credentials
            app_id = os.getenv('FACEBOOK_APP_ID')
            app_secret = os.getenv('FACEBOOK_APP_SECRET')
            access_token = os.getenv('FACEBOOK_ACCESS_TOKEN')
            page_id = os.getenv('FACEBOOK_PAGE_ID')
            
            # Debug logging with partial values for verification
            logger.info("Facebook Credentials Check:")
            logger.info(f"App ID: {'✓ Present' if app_id else '✗ Missing'} ({app_id[:4]}... if present)")
            logger.info(f"App Secret: {'✓ Present' if app_secret else '✗ Missing'} ({app_secret[:4]}... if present)")
            logger.info(f"Access Token: {'✓ Present' if access_token else '✗ Missing'} (Length: {len(access_token) if access_token else 0})")
            logger.info(f"Page ID: {'✓ Present' if page_id else '✗ Missing'} ({page_id if page_id else 'None'})")
            
            # Validate credentials format
            if access_token and not access_token.startswith('EAA'):
                logger.error("Access token format appears invalid - should start with 'EAA'")
                return jsonify({
                    'error': 'Invalid access token format',
                    'details': 'The access token should be a long string starting with "EAA"',
                    'help': 'Please generate a new access token from Meta Business Suite'
                }), 400
                
            if page_id and not page_id.isdigit():
                logger.error("Page ID should contain only numbers")
                return jsonify({
                    'error': 'Invalid page ID format',
                    'details': 'The page ID should contain only numbers',
                    'help': 'You can find your page ID in the Meta Business Suite URL'
                }), 400

            # Validate credentials presence
            missing_credentials = []
            if not app_id:
                missing_credentials.append('FACEBOOK_APP_ID')
            if not app_secret:
                missing_credentials.append('FACEBOOK_APP_SECRET')
            if not access_token:
                missing_credentials.append('FACEBOOK_ACCESS_TOKEN')
            if not page_id:
                missing_credentials.append('FACEBOOK_PAGE_ID')
            
            if missing_credentials:
                logger.error(f"Missing Meta API credentials: {', '.join(missing_credentials)}")
                return jsonify({
                    'error': 'Meta API credentials not configured properly',
                    'missing_credentials': missing_credentials,
                    'setup_instructions': '''
                    1. Open your .env file in the back-end directory
                    2. Add these lines (replace with your actual values):
                    
                    FACEBOOK_APP_ID=123456789
                    FACEBOOK_APP_SECRET=abcdef123456789
                    FACEBOOK_ACCESS_TOKEN=EAAxxxxx...
                    FACEBOOK_PAGE_ID=987654321
                    
                    3. Save the file
                    4. Restart the Flask server
                    '''
                }), 400
            
            try:
                # Initialize the Facebook Ads API
                FacebookAdsApi.init(app_id, app_secret, access_token)
            
                # Test the connection with minimal permissions first
                try:
                    # Verify page access directly
                    page = Page(page_id)
                    page_data = page.api_get(fields=['name', 'id'])
                    
                    return jsonify({
                        'message': 'Connected to Meta Ads successfully',
                        'page_name': page_data.get('name'),
                        'page_id': page_data.get('id')
                    }), 200
                except Exception as page_error:
                    error_message = str(page_error)
                    if 'pages_read_engagement' in error_message or 'Page Public Content Access' in error_message:
                        required_permissions = [
                            'pages_read_engagement',
                            'pages_manage_metadata',
                            'pages_show_list',
                            'leads_retrieval',
                            'ads_management',
                            'ads_read',
                            'business_management'
                        ]
                        return jsonify({
                            'error': 'Missing Facebook Page permissions',
                            'required_permissions': required_permissions,
                            'setup_instructions': '''
                            To fix this:
                            1. Go to https://developers.facebook.com/apps/
                            2. Select your app
                            3. Go to App Dashboard > Settings > Basic
                            4. Add these permissions to your app:
                               - pages_read_engagement
                               - pages_manage_metadata
                               - pages_show_list
                               - leads_retrieval
                               - ads_management
                               - ads_read
                               - business_management
                            5. Go to App Dashboard > Facebook Login > Settings
                            6. Add these permissions to the "User Data Deletion" section
                            7. Save changes
                            8. Generate a new access token with these permissions
                            9. Update your .env file with the new token
                            '''
                        }), 403
                    else:
                        logger.error(f"Meta API connection error: {error_message}")
                        return jsonify({
                            'error': 'Failed to connect to Meta API',
                            'details': error_message
                        }), 500
            except Exception as e:
                logger.error(f"Meta API initialization error: {str(e)}")
                return jsonify({
                    'error': 'Failed to initialize Meta API',
                    'details': str(e)
                }), 500
                
        except Exception as e:
            logger.error(f"Unexpected error in connect_meta: {str(e)}")
            return jsonify({
                'error': 'An unexpected error occurred',
                'details': str(e)
            }), 500

    @app.route('/fetch_meta_leads', methods=['GET'])
    @jwt_required()
    def fetch_meta_leads():
        try:
            # Initialize the Facebook Ads API
            app_id = os.getenv('FACEBOOK_APP_ID')
            app_secret = os.getenv('FACEBOOK_APP_SECRET')
            access_token = os.getenv('FACEBOOK_ACCESS_TOKEN')
            page_id = os.getenv('FACEBOOK_PAGE_ID')
            
            if not all([app_id, app_secret, access_token, page_id]):
                return jsonify({'error': 'Facebook credentials not configured'}), 500
            
            FacebookAdsApi.init(app_id, app_secret, access_token)
            
            # Get the page and its lead gen forms
            page = Page(page_id)
            forms = page.get_leadgen_forms()
            
            count = 0
            for form in forms:
                # Get leads from each form
                leads = LeadgenForm(form['id']).get_leads()
                
                for lead_data in leads:
                    # Extract lead information
                    field_data = lead_data['field_data']
                    lead_info = {item['name']: item['values'][0] for item in field_data}
                    
                    # Create new lead
                    lead = Lead(
                        name=lead_info.get('full_name', ''),
                        email=lead_info.get('email', ''),
                        phone=lead_info.get('phone_number', ''),
                        source='meta_ads',
                        status='new'
                    )
                    db.session.add(lead)
                    count += 1
            
            db.session.commit()
            return jsonify({'message': 'Leads fetched successfully', 'count': count}), 200
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/leads', methods=['GET'])
    @jwt_required()
    def get_leads():
        try:
            current_user = get_current_user()
            if not current_user:
                logger.error("No authenticated user found")
                return jsonify({'error': 'Authentication required'}), 401

            logger.info(f"Get leads request from user: {current_user.email} (role: {current_user.role}, id: {current_user.id})")
            
            # Admin sees all leads, staff sees only their assigned leads
            if current_user.role == 'admin':
                logger.info("Admin user - fetching all leads")
                leads = Lead.query.order_by(Lead.created_at.desc()).all()
            else:
                logger.info(f"Staff user - fetching leads assigned to staff ID: {current_user.id}")
                leads = Lead.query.filter_by(assigned_staff_id=current_user.id).order_by(Lead.created_at.desc()).all()
            
            logger.info(f"Found {len(leads)} leads for user")
            
            lead_list = []
            for lead in leads:
                try:
                    lead_data = {
                        'id': lead.id,
                        'name': lead.name,
                        'email': lead.email,
                        'phone': lead.phone,
                        'city': lead.city,
                        'source': lead.source,
                        'status': lead.status,
                        'created_at': lead.created_at.isoformat() if lead.created_at else None,
                        'assigned_staff_id': lead.assigned_staff_id,
                        'assigned_staff_name': lead.assigned_staff.name if lead.assigned_staff else None
                    }
                    lead_list.append(lead_data)
                except Exception as e:
                    logger.error(f"Error processing lead {lead.id}: {str(e)}")
                    continue
            
            logger.info(f"Returning {len(lead_list)} leads to user")
            
            # Log a sample of leads being returned
            if lead_list:
                sample_size = min(3, len(lead_list))
                logger.info(f"Sample of first {sample_size} leads being returned:")
                for lead in lead_list[:sample_size]:
                    logger.info(f"Lead ID: {lead['id']}, Name: {lead['name']}, Assigned to: {lead['assigned_staff_name']}")
            
            return jsonify(lead_list), 200
            
        except Exception as e:
            logger.error(f"Error in get_leads: {str(e)}")
            return jsonify({'error': str(e)}), 500

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

    @app.route('/assign_leads', methods=['POST'])
    @jwt_required()
    def assign_leads():
        try:
            current_user = get_current_user()
            if not current_user or current_user.role != 'admin':
                return jsonify({'error': 'Only admin can assign leads'}), 403

            data = request.get_json()
            if not data or 'lead_ids' not in data or 'staff_id' not in data:
                return jsonify({'error': 'Missing required fields'}), 400

            lead_ids = data['lead_ids']
            staff_id = data['staff_id']

            # Verify staff exists
            staff = User.query.filter_by(id=staff_id, role='staff').first()
            if not staff:
                return jsonify({'error': 'Invalid staff ID'}), 400

            # Update leads
            updated_count = 0
            for lead_id in lead_ids:
                lead = Lead.query.get(lead_id)
                if lead:
                    lead.assigned_staff_id = staff_id
                    updated_count += 1

            db.session.commit()
            return jsonify({
                'message': f'Successfully assigned {updated_count} leads to staff member',
                'assigned_count': updated_count
            }), 200

        except Exception as e:
            logger.error(f"Error in assign_leads: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/unassigned_leads', methods=['GET'])
    @jwt_required()
    def get_unassigned_leads():
        try:
            current_user = get_current_user()
            if not current_user or current_user.role != 'admin':
                return jsonify({'error': 'Only admin can view unassigned leads'}), 403

            unassigned_leads = Lead.query.filter_by(assigned_staff_id=None).all()
            lead_list = [{
                'id': lead.id,
                'name': lead.name,
                'email': lead.email,
                'phone': lead.phone,
                'city': lead.city,
                'source': lead.source,
                'status': lead.status,
                'created_at': lead.created_at.isoformat() if lead.created_at else None
            } for lead in unassigned_leads]

            return jsonify(lead_list), 200

        except Exception as e:
            logger.error(f"Error in get_unassigned_leads: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/staff_stats', methods=['GET'])
    @jwt_required()
    def get_staff_stats():
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            if current_user.role == 'admin':
                # For admin, get stats for all staff
                staff_members = User.query.filter_by(role='staff').all()
                stats = []
                for staff in staff_members:
                    total_leads = Lead.query.filter_by(assigned_staff_id=staff.id).count()
                    new_leads = Lead.query.filter_by(assigned_staff_id=staff.id, status='new').count()
                    contacted = Lead.query.filter_by(assigned_staff_id=staff.id, status='contacted').count()
                    converted = Lead.query.filter_by(assigned_staff_id=staff.id, status='converted').count()
                    
                    stats.append({
                        'staff_id': staff.id,
                        'staff_name': staff.name,
                        'staff_email': staff.email,
                        'total_leads': total_leads,
                        'new_leads': new_leads,
                        'contacted_leads': contacted,
                        'converted_leads': converted
                    })
                return jsonify(stats), 200
            else:
                # For staff, get their own stats
                total_leads = Lead.query.filter_by(assigned_staff_id=current_user.id).count()
                new_leads = Lead.query.filter_by(assigned_staff_id=current_user.id, status='new').count()
                contacted = Lead.query.filter_by(assigned_staff_id=current_user.id, status='contacted').count()
                converted = Lead.query.filter_by(assigned_staff_id=current_user.id, status='converted').count()
                
                stats = {
                    'staff_id': current_user.id,
                    'staff_name': current_user.name,
                    'staff_email': current_user.email,
                    'total_leads': total_leads,
                    'new_leads': new_leads,
                    'contacted_leads': contacted,
                    'converted_leads': converted
                }
                return jsonify(stats), 200

        except Exception as e:
            logger.error(f"Error in get_staff_stats: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/leads/<int:lead_id>/status', methods=['PUT'])
    @jwt_required()
    def update_lead_status(lead_id):
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            # Get the lead
            lead = Lead.query.get(lead_id)
            if not lead:
                return jsonify({'error': 'Lead not found'}), 404

            # Verify user has permission to update this lead
            if current_user.role != 'admin' and lead.assigned_staff_id != current_user.id:
                return jsonify({'error': 'Unauthorized to update this lead'}), 403

            data = request.get_json()
            if 'status' not in data:
                return jsonify({'error': 'Status is required'}), 400

            # Update lead status
            lead.status = data['status']
            lead.updated_at = datetime.datetime.utcnow()
            
            # Add followup if notes are provided
            if 'notes' in data and data['notes']:
                followup = Followup(
                    lead_id=lead_id,
                    staff_id=current_user.id,
                    followup_date=datetime.datetime.utcnow(),
                    notes=data['notes']
                )
                db.session.add(followup)

            db.session.commit()
            return jsonify({
                'message': 'Lead status updated successfully',
                'lead_id': lead_id,
                'new_status': lead.status
            }), 200

        except Exception as e:
            logger.error(f"Error in update_lead_status: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/leads/<int:lead_id>/followups', methods=['GET', 'POST'])
    @jwt_required()
    def handle_followups(lead_id):
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            # Get the lead
            lead = Lead.query.get(lead_id)
            if not lead:
                return jsonify({'error': 'Lead not found'}), 404

            # Verify user has permission to access this lead
            if current_user.role != 'admin' and lead.assigned_staff_id != current_user.id:
                return jsonify({'error': 'Unauthorized to access this lead'}), 403

            if request.method == 'GET':
                # Get all followups for this lead
                followups = Followup.query.filter_by(lead_id=lead_id).order_by(Followup.followup_date.desc()).all()
                return jsonify([{
                    'id': f.id,
                    'staff_id': f.staff_id,
                    'date': f.followup_date.isoformat(),
                    'notes': f.notes
                } for f in followups]), 200

            else:  # POST
                data = request.get_json()
                if 'notes' not in data:
                    return jsonify({'error': 'Notes are required'}), 400

                # Create new followup
                followup = Followup(
                    lead_id=lead_id,
                    staff_id=current_user.id,
                    followup_date=datetime.datetime.utcnow(),
                    notes=data['notes']
                )
                db.session.add(followup)
                
                # Update lead status if provided
                if 'status' in data:
                    lead.status = data['status']
                    lead.updated_at = datetime.datetime.utcnow()

                db.session.commit()
                return jsonify({
                    'message': 'Followup added successfully',
                    'followup_id': followup.id
                }), 201

        except Exception as e:
            logger.error(f"Error in handle_followups: {str(e)}")
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    @app.route('/staff/<int:staff_id>/activity', methods=['GET'])
    @jwt_required()
    def get_staff_activity(staff_id):
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            if current_user.role != 'admin':
                return jsonify({'error': 'Unauthorized'}), 403

            # Find the staff member
            staff = User.query.get(staff_id)
            if not staff:
                return jsonify({'error': 'Staff member not found'}), 404

            # Get recent followups
            followups = Followup.query.filter_by(staff_id=staff.id).order_by(Followup.followup_date.desc()).limit(5).all()
            
            # Get recent lead status changes
            leads = Lead.query.filter_by(assigned_staff_id=staff.id).order_by(Lead.updated_at.desc()).limit(5).all()
            
            # Get recent sales
            sales = Sale.query.filter_by(staff_id=staff.id).order_by(Sale.sale_date.desc()).limit(5).all()

            activities = []

            # Add followups to activities
            for followup in followups:
                activities.append({
                    'type': 'contact',
                    'title': 'Lead Followup',
                    'description': f'Followed up with lead: {followup.notes}',
                    'timestamp': followup.followup_date.isoformat()
                })

            # Add lead status changes to activities
            for lead in leads:
                activities.append({
                    'type': lead.status,
                    'title': 'Lead Status Update',
                    'description': f'Updated lead status to {lead.status}',
                    'timestamp': lead.updated_at.isoformat() if lead.updated_at else lead.created_at.isoformat()
                })

            # Add sales to activities
            for sale in sales:
                activities.append({
                    'type': 'conversion',
                    'title': 'New Sale',
                    'description': f'Closed sale worth ₹{sale.amount}',
                    'timestamp': sale.sale_date.isoformat()
                })

            # Sort activities by timestamp
            activities.sort(key=lambda x: x['timestamp'], reverse=True)

            return jsonify(activities[:10]), 200

        except Exception as e:
            logger.error(f"Error in get_staff_activity: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/update_activity', methods=['POST'])
    @jwt_required()
    def update_activity():
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            data = request.get_json()
            current_user.last_active = datetime.datetime.utcnow()
            
            # Update cursor position if provided
            if 'cursor_x' in data and 'cursor_y' in data:
                current_user.cursor_x = data['cursor_x']
                current_user.cursor_y = data['cursor_y']
                current_user.last_cursor_move = datetime.datetime.utcnow()

            db.session.commit()
            return jsonify({'message': 'Activity updated successfully'}), 200

        except Exception as e:
            logger.error(f"Error updating activity: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/reports', methods=['GET', 'POST', 'OPTIONS'])
    @jwt_required()
    def get_reports():
        # Handle OPTIONS request first
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            # Get date range from request
            start_date = None
            end_date = None
            if request.method == 'POST':
                data = request.get_json()
                start_date = datetime.datetime.strptime(data.get('start_date', ''), '%Y-%m-%d').date() if data.get('start_date') else None
                end_date = datetime.datetime.strptime(data.get('end_date', ''), '%Y-%m-%d').date() if data.get('end_date') else None

            # Base query for leads
            query = Lead.query
            if start_date:
                query = query.filter(Lead.created_at >= start_date)
            if end_date:
                query = query.filter(Lead.created_at <= end_date)

            # Get all leads
            leads = query.all()

            # Calculate stats
            total_leads = len(leads)
            converted_leads = sum(1 for lead in leads if lead.status == 'converted')
            pending_leads = sum(1 for lead in leads if lead.status == 'new' or lead.status == 'contacted')
            lost_leads = sum(1 for lead in leads if lead.status == 'lost')

            # Calculate leads by source
            leads_by_source = {}
            for lead in leads:
                source = lead.source or 'unknown'
                leads_by_source[source] = leads_by_source.get(source, 0) + 1

            # Calculate conversion rate trend (last 7 days)
            today = datetime.datetime.utcnow().date()
            conversion_rates = []
            labels = []
            for i in range(6, -1, -1):
                date = today - datetime.timedelta(days=i)
                daily_leads = [lead for lead in leads if lead.created_at and lead.created_at.date() == date]
                daily_converted = sum(1 for lead in daily_leads if lead.status == 'converted')
                rate = (daily_converted / len(daily_leads) * 100) if daily_leads else 0
                conversion_rates.append(rate)
                labels.append(date.strftime('%Y-%m-%d'))

            response = jsonify({
                'stats': {
                    'total': total_leads,
                    'converted': converted_leads,
                    'pending': pending_leads,
                    'lost': lost_leads
                },
                'charts': {
                    'leadsBySource': {
                        'labels': list(leads_by_source.keys()),
                        'data': list(leads_by_source.values())
                    },
                    'conversionRate': {
                        'labels': labels,
                        'data': conversion_rates
                    }
                }
            })
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response, 200

        except Exception as e:
            logger.error(f"Error in get_reports: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/export_report', methods=['POST'])
    @jwt_required()
    def export_report():
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401

            # Get date range from request
            data = request.get_json()
            start_date = datetime.datetime.strptime(data.get('start_date', ''), '%Y-%m-%d').date() if data.get('start_date') else None
            end_date = datetime.datetime.strptime(data.get('end_date', ''), '%Y-%m-%d').date() if data.get('end_date') else None

            # Base query for leads
            query = Lead.query
            if start_date:
                query = query.filter(Lead.created_at >= start_date)
            if end_date:
                query = query.filter(Lead.created_at <= end_date)

            # Get all leads
            leads = query.all()

            # Create DataFrame
            df = pd.DataFrame([{
                'Name': lead.name,
                'Email': lead.email,
                'Phone': lead.phone,
                'City': lead.city,
                'Source': lead.source,
                'Status': lead.status,
                'Created At': lead.created_at.strftime('%Y-%m-%d %H:%M:%S') if lead.created_at else None,
                'Assigned To': lead.assigned_staff.name if lead.assigned_staff else 'Unassigned'
            } for lead in leads])

            # Create Excel writer
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                # Write leads data
                df.to_excel(writer, sheet_name='Leads', index=False)
                
                # Get workbook and worksheet
                workbook = writer.book
                worksheet = writer.sheets['Leads']
                
                # Add formats
                header_format = workbook.add_format({
                    'bold': True,
                    'bg_color': '#2563eb',
                    'font_color': 'white',
                    'border': 1
                })
                
                # Format headers
                for col_num, value in enumerate(df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                
                # Auto-adjust column widths
                for idx, col in enumerate(df):
                    max_length = max(
                        df[col].astype(str).apply(len).max(),
                        len(str(col))
                    )
                    worksheet.set_column(idx, idx, max_length + 2)

            # Prepare response
            output.seek(0)
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
            )

        except Exception as e:
            logger.error(f"Error in export_report: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/settings', methods=['GET', 'POST', 'OPTIONS'])
    @jwt_required()
    def handle_settings():
        # Handle OPTIONS request first
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        try:
            current_user = get_current_user()
            if not current_user or current_user.role != 'admin':
                return jsonify({'error': 'Unauthorized'}), 403

            if request.method == 'GET':
                # Return current settings
                response = jsonify({
                    'inactivityTimeout': 5,  # Default value
                    'maxLeadsPerStaff': 50,  # Default value
                    'autoAssignLeads': True  # Default value
                })
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                return response, 200

            else:  # POST
                data = request.get_json()
                # Here you would typically save these settings to a database
                # For now, we'll just return success
                response = jsonify({'message': 'Settings saved successfully'})
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                return response, 200

        except Exception as e:
            logger.error(f"Error in handle_settings: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/settings/meta', methods=['GET', 'POST', 'OPTIONS'])
    @jwt_required()
    def handle_meta_settings():
        # Handle OPTIONS request first
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        try:
            current_user = get_current_user()
            if not current_user or current_user.role != 'admin':
                return jsonify({'error': 'Unauthorized'}), 403

            if request.method == 'GET':
                # Return current Meta settings (without sensitive data)
                response = jsonify({
                    'appId': os.getenv('FACEBOOK_APP_ID', ''),
                    'pageId': os.getenv('FACEBOOK_PAGE_ID', '')
                })
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                return response, 200

            else:  # POST
                data = request.get_json()
                
                # Update environment variables
                if 'appId' in data:
                    os.environ['FACEBOOK_APP_ID'] = data['appId']
                if 'appSecret' in data:
                    os.environ['FACEBOOK_APP_SECRET'] = data['appSecret']
                if 'accessToken' in data:
                    os.environ['FACEBOOK_ACCESS_TOKEN'] = data['accessToken']
                if 'pageId' in data:
                    os.environ['FACEBOOK_PAGE_ID'] = data['pageId']

                # Here you would typically save these settings to a secure storage
                # For now, we'll just return success
                response = jsonify({'message': 'Meta settings saved successfully'})
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                return response, 200

        except Exception as e:
            logger.error(f"Error in handle_meta_settings: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/settings/whatsapp', methods=['GET', 'POST', 'OPTIONS'])
    @jwt_required()
    def handle_whatsapp_settings():
        if request.method == 'OPTIONS':
            response = jsonify({'message': 'OK'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        try:
            current_user = get_current_user()
            if not current_user or current_user.role != 'admin':
                return jsonify({'error': 'Unauthorized'}), 403

            if request.method == 'GET':
                response = jsonify({
                    'number': os.getenv('WHATSAPP_NUMBER', ''),
                    'message': os.getenv('WHATSAPP_MESSAGE', 'Hello {name}, thank you for your interest in our services.')
                })
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                return response, 200

            else:  # POST
                data = request.get_json()
                
                if 'number' in data:
                    os.environ['WHATSAPP_NUMBER'] = data['number']
                if 'message' in data:
                    os.environ['WHATSAPP_MESSAGE'] = data['message']

                response = jsonify({'message': 'WhatsApp settings saved successfully'})
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                return response, 200

        except Exception as e:
            logger.error(f"Error in handle_whatsapp_settings: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/inactive_staff_alerts', methods=['GET'])
    @jwt_required()
    def get_inactive_staff_alerts():
        try:
            current_user = get_current_user()
            if not current_user or current_user.role != 'admin':
                return jsonify({'error': 'Unauthorized'}), 403

            now = datetime.datetime.utcnow()
            activity_threshold = now - datetime.timedelta(minutes=5)
            cursor_threshold = now - datetime.timedelta(minutes=2)
            
            # Get inactive staff members
            inactive_staff = User.query.filter(
                User.role == 'staff',
                User.last_active.isnot(None),
                User.last_active < activity_threshold,
                (User.last_cursor_move.is_(None) | (User.last_cursor_move < cursor_threshold))
            ).all()

            alerts = []
            for staff in inactive_staff:
                last_cursor_move = staff.last_cursor_move.strftime('%Y-%m-%d %H:%M:%S') if staff.last_cursor_move else 'Never'
                last_active = staff.last_active.strftime('%Y-%m-%d %H:%M:%S') if staff.last_active else 'Never'
                
                alerts.append({
                    'staff_id': staff.id,
                    'staff_name': staff.name,
                    'staff_email': staff.email,
                    'last_cursor_move': last_cursor_move,
                    'last_active': last_active,
                    'inactive_duration': int((now - staff.last_active).total_seconds() / 60) if staff.last_active else 0
                })

            return jsonify(alerts), 200

        except Exception as e:
            logger.error(f"Error in get_inactive_staff_alerts: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/staff/monitor', methods=['GET'])
    @jwt_required()
    def monitor_staff():
        try:
            # Get current user and verify admin status
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user or not current_user.is_admin:
                return jsonify({'error': 'Unauthorized access'}), 403

            # Get all staff members
            staff_members = User.query.filter_by(role='staff').all()
            
            staff_data = []
            for staff in staff_members:
                # Get active leads count
                active_leads = Lead.query.filter_by(
                    assigned_staff_id=staff.id,
                    status='active'
                ).count()
                
                # Calculate conversion rate
                total_leads = Lead.query.filter_by(assigned_staff_id=staff.id).count()
                converted_leads = Lead.query.filter_by(
                    assigned_staff_id=staff.id,
                    status='converted'
                ).count()
                conversion_rate = (converted_leads / total_leads * 100) if total_leads > 0 else 0
                
                # Get today's calls
                today = datetime.now().date()
                today_calls = Followup.query.filter(
                    Followup.staff_id == staff.id,
                    func.date(Followup.timestamp) == today
                ).count()
                
                # Calculate average response time (in minutes)
                followups = Followup.query.filter_by(staff_id=staff.id).all()
                response_times = []
                for followup in followups:
                    if followup.response_time:
                        response_times.append(followup.response_time)
                avg_response_time = sum(response_times) / len(response_times) if response_times else 0
                
                # Check if staff is active (active within last 5 minutes)
                five_minutes_ago = datetime.now() - datetime.timedelta(minutes=5)
                is_active = staff.last_active and staff.last_active > five_minutes_ago
                
                staff_data.append({
                    'id': staff.id,
                    'name': staff.name,
                    'email': staff.email,
                    'activeLeads': active_leads,
                    'conversionRate': round(conversion_rate, 1),
                    'avgResponseTime': round(avg_response_time, 1),
                    'todayCalls': today_calls,
                    'isActive': is_active,
                    'lastActive': staff.last_active.strftime('%Y-%m-%d %H:%M:%S') if staff.last_active else None
                })

            # Get performance data for chart
            performance_data = {
                'labels': [],
                'data': []
            }
            
            # Get last 7 days performance
            for i in range(7):
                date = datetime.now().date() - datetime.timedelta(days=i)
                daily_leads = Lead.query.filter(func.date(Lead.created_at) == date).count()
                daily_conversions = Lead.query.filter(
                    func.date(Lead.created_at) == date,
                    Lead.status == 'converted'
                ).count()
                daily_rate = (daily_conversions / daily_leads * 100) if daily_leads > 0 else 0
                
                performance_data['labels'].insert(0, date.strftime('%Y-%m-%d'))
                performance_data['data'].insert(0, round(daily_rate, 1))

            return jsonify({
                'staff': staff_data,
                'performance': performance_data
            })

        except Exception as e:
            app.logger.error(f"Error in staff monitoring: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500

    @app.route('/staff/<int:staff_id>/reset-password', methods=['POST'])
    @jwt_required()
    def reset_staff_password(staff_id):
        try:
            # Get current user and verify admin status
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user or not current_user.is_admin:
                return jsonify({'error': 'Unauthorized access'}), 403

            # Get staff member
            staff = User.query.get(staff_id)
            if not staff:
                return jsonify({'error': 'Staff member not found'}), 404

            # Generate new random password
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            staff.password = generate_password_hash(new_password)
            
            # Save to database
            db.session.commit()

            # Send email with new password
            msg = Message(
                'Password Reset',
                sender='admin@moneykrisha.com',
                recipients=[staff.email]
            )
            msg.body = f'''Your password has been reset by the administrator.
Your new password is: {new_password}
Please change your password after logging in.'''
            
            mail.send(msg)

            return jsonify({'message': 'Password reset successful'}), 200

        except Exception as e:
            app.logger.error(f"Error in password reset: {str(e)}")
            return jsonify({'error': 'Failed to reset password'}), 500

    # Update the inactivity checker to consider cursor movement
    def check_inactivity():
        with app.app_context():
            try:
                from models import User
                now = datetime.datetime.utcnow()
                activity_threshold = now - datetime.timedelta(minutes=5)
                cursor_threshold = now - datetime.timedelta(minutes=2)  # Cursor must move every 2 minutes
                
                # Check staff members who are logged in but inactive
                inactive_staff = User.query.filter(
                    User.role == 'staff',
                    User.last_active.isnot(None),
                    User.last_active < activity_threshold,
                    (User.last_cursor_move.is_(None) | (User.last_cursor_move < cursor_threshold))
                ).all()

                for staff in inactive_staff:
                    last_cursor_move = staff.last_cursor_move.strftime('%Y-%m-%d %H:%M:%S') if staff.last_cursor_move else 'Never'
                    last_active = staff.last_active.strftime('%Y-%m-%d %H:%M:%S') if staff.last_active else 'Never'
                    
                    logging.warning(
                        f"Alert: Staff member {staff.name} ({staff.email}) is inactive!\n"
                        f"Last cursor movement: {last_cursor_move}\n"
                        f"Last active: {last_active}"
                    )
                    
                    # You could add additional actions here, such as:
                    # - Sending notifications to admin
                    # - Updating staff status
                    # - Recording in activity log

                db.session.commit()
            except Exception as e:
                logging.error(f"Scheduler Error in check_inactivity: {str(e)}")

    # Add Scheduler Job
    with app.app_context():
        scheduler.add_job(
            check_inactivity, 
            'interval', 
            minutes=1, 
            replace_existing=True, 
            misfire_grace_time=30,
            id='inactivity_checker'
        )

    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))

    return app  # ✅ Return the Flask app

# Run the App
app = create_app()

if __name__ == '__main__':
    app.run(debug=False)
