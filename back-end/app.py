import os
import datetime
import logging
import atexit
from flask import Flask, request, jsonify
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

# Load environment variables
load_dotenv()

# Factory Function
def create_app():
    app = Flask(__name__)

    # Force recreate database in development
    if os.path.exists('leads.db'):
        os.remove('leads.db')

    # Flask Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leads.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'

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
    
    # Configure CORS
    CORS(app, resources={
        r"/*": {
            "origins": [
                "http://localhost:5000",
                "http://127.0.0.1:5000",
                "http://localhost:5500",
                "http://127.0.0.1:5500",
                "http://localhost",
                "http://127.0.0.1"
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "Accept"],
            "expose_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
            "allow_credentials": True
        }
    })
    
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
        
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create initial admin user if no users exist
        if not User.query.first():
            admin_user = User(
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin',
                name='Admin User'
            )
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Created initial admin user (email: admin@example.com, password: admin123)")
            
        logger.info("Database initialized successfully with all tables and columns.")

    # Register Routes
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
                # Update last active time
                user.last_active = datetime.datetime.utcnow()
                db.session.commit()
                
                # Create access token with user object
                access_token = create_access_token(identity=user)
                
                return jsonify({
                    'access_token': access_token,
                    'role': user.role,
                    'email': user.email,
                    'name': user.name,
                    'id': user.id
                }), 200

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

    @app.route('/profile', methods=['GET'])
    @jwt_required()
    def get_profile():
        try:
            current_user = get_current_user()
            if not current_user:
                return jsonify({'message': 'User not found'}), 404
            return jsonify({
                'email': current_user.email,
                'name': current_user.name,
                'role': current_user.role,
                'phone': current_user.phone,
                'dob': current_user.dob.strftime('%Y-%m-%d') if current_user.dob and isinstance(current_user.dob, (datetime.date, datetime.datetime)) else current_user.dob
            })
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

    @app.route('/staff', methods=['GET'])
    @jwt_required()
    def get_staff():
        try:
            current_user = get_current_user()
            if current_user.role != 'admin':
                return jsonify({'message': 'Unauthorized'}), 403

            staff = User.query.all()
            return jsonify([{
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "name": user.name,
                "last_active": user.last_active.isoformat() if user.last_active else None
            } for user in staff])
        except Exception as e:
            logger.error(f"Error: {e}")
            return jsonify({'message': 'An error occurred'}), 500

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
                            city=str(row['city']).strip() if 'city' in row else None,
                            assigned_staff_id=current_user.id if current_user.role == 'staff' else None
                        )
                        
                        if current_user.role == 'staff':
                            logger.info(f"Assigning lead {lead.name} to staff member {current_user.id}")
                            assigned_count += 1
                        else:
                            logger.info(f"User is admin, lead {lead.name} will remain unassigned")
                        
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
                
                # Verify the leads were saved and assigned correctly
                if current_user.role == 'staff':
                    saved_leads = Lead.query.filter_by(
                        source='csv_import',
                        assigned_staff_id=current_user.id
                    ).order_by(Lead.created_at.desc()).limit(5).all()
                    
                    logger.info(f'Verification: Found {len(saved_leads)} leads assigned to staff ID {current_user.id}')
                    for lead in saved_leads:
                        logger.info(f'Verified lead: {lead.name}, assigned_staff_id: {lead.assigned_staff_id}')
                
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
            # Initialize the Facebook Ads API
            app_id = os.getenv('FACEBOOK_APP_ID')
            app_secret = os.getenv('FACEBOOK_APP_SECRET')
            access_token = os.getenv('FACEBOOK_ACCESS_TOKEN')
            
            if not all([app_id, app_secret, access_token]):
                return jsonify({'error': 'Facebook credentials not configured'}), 500
            
            FacebookAdsApi.init(app_id, app_secret, access_token)
            
            # Test the connection
            try:
                Page(os.getenv('FACEBOOK_PAGE_ID')).api_get()
                return jsonify({'message': 'Connected to Meta Ads successfully'}), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500
                
        except Exception as e:
            return jsonify({'error': str(e)}), 500

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
                        'assigned_staff_id': lead.assigned_staff_id
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
                    logger.info(f"Lead ID: {lead['id']}, Name: {lead['name']}, Assigned to: {lead['assigned_staff_id']}")
            
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

    # Inactivity Checker (Background Job)
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

    # Add Scheduler Job
    with app.app_context():
        scheduler.add_job(check_inactivity, 'interval', minutes=1, replace_existing=True, misfire_grace_time=30)

    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))

    return app  # ✅ Return the Flask app

# Run the App
app = create_app()

if __name__ == '__main__':
    app.run(debug=False)
