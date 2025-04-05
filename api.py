from flask_cors import CORS
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from datetime import datetime
import datetime as dt

# Initialize the Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # Use SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'qwertyuiop1234sdf'  # Replace with a secure key in production

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    empid = db.Column(db.Integer, unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    geography = db.Column(db.String(128), nullable=False)
    operatingCountry = db.Column(db.String(128), nullable=False)
    officeCity = db.Column(db.String(128), nullable=False)
    baseLocation = db.Column(db.String(128), nullable=False)
    accountName = db.Column(db.String(128), nullable=False)
    projectName = db.Column(db.String(128), nullable=False)
    transportData = db.Column(db.JSON, nullable=False)
    numberOfDays = db.Column(db.Integer, nullable=False)
    emissionData = db.Column(db.JSON, nullable=True)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/admin-signup', methods=['POST'])
def adminSignup():
    data = request.json
    name = data.get('name')
    email = data.get('emailId')
    password = data.get('newPassword')

    if not email or not password:
        return jsonify({'error': 'email, and password fields are required'}), 400
    
    if Admin.query.filter_by(email=email).first():
        return jsonify({'error': 'email already in use'})
    
    hashedPassword = bcrypt.generate_password_hash(password).decode('utf-8')

    new_admin = Admin(name=name, email=email, password=hashedPassword)
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({'message': 'Admin registered successfully'}), 201

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    empid = data.get('employeeId')
    email = data.get('emailId')
    password = data.get('newPassword')
    geography = data.get('geography')
    operatingCountry = data.get('operatingCountry')
    officeCity = data.get('officeCity')
    baseLocation = data.get('baseLocation')
    accountName = data.get('accountName')
    projectName = data.get('projectName')
    transportData = data.get('transportData')  # Expecting a list
    numberOfDays = data.get('numberOfDays')

    if not empid or not email or not password:
        return jsonify({'error': 'empid, email, and password fields are required'}), 400

    # Check if the user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already in use'}), 409
    if User.query.filter_by(empid=empid).first():
        return jsonify({'error': 'empid already in use'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Ensure transportData is stored as a list of objects with month and year
    now = datetime.now()
    formatted_transport_data = []
    
    if isinstance(transportData, dict):  # If single entry is received
        transportData = [transportData]

    for entry in transportData:
        formatted_transport_data.append({
            'month': now.month,
            'year': now.year,
            'distance': entry['distance'],
            'fuel': entry['fuel'],
            'mode': entry['mode']
        })

    # Create a new user
    new_user = User(
        name=name, empid=empid, email=email, password=hashed_password,
        geography=geography, operatingCountry=operatingCountry,
        officeCity=officeCity, baseLocation=baseLocation,
        accountName=accountName, projectName=projectName,
        transportData=formatted_transport_data,  # Store as a list
        numberOfDays=numberOfDays
    )
    
    db.session.add(new_user)
    
    # Calculate emission
    emission = calculate_emission(new_user)
    
    # Ensure emissionData is a list
    if new_user.emissionData is None:
        new_user.emissionData = []
    
    new_emission_entry = {
        'month': now.month,
        'year': now.year,
        'emission': emission
    }
    
    new_user.emissionData.append(new_emission_entry)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/admin-signin', methods=['POST', 'OPTIONS'])
def adminSignin():
    if request.method == 'OPTIONS':
        return jsonify({"message": "Preflight check"}), 200
    
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    admin = Admin.query.filter_by(email=email).first()
    if not admin or not bcrypt.check_password_hash(admin.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Add role information to distinguish admin
    access_token = create_access_token(
        identity=str(admin.id), 
        additional_claims={"role": "admin"},
        expires_delta=dt.timedelta(hours=1)
    )
    
    return jsonify({'message': 'Login successful', 'access_token': access_token, 'redirect': '/admin-dashboard'}), 200

@app.route('/signin', methods=['POST', 'OPTIONS'])
def signin():
    if request.method == 'OPTIONS':
        return jsonify({"message": "Preflight check"}), 200

    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Add role information to distinguish user
    access_token = create_access_token(
        identity=str(user.id), 
        additional_claims={"role": "user"},
        expires_delta=dt.timedelta(hours=1)
    )

    return jsonify({'message': 'Login successful', 'access_token': access_token, 'redirect': '/dashboard'}), 200

@app.route('/checktoken', methods=['GET'])
@jwt_required()
def checktoken():
    current_id = get_jwt_identity()
    claims = get_jwt()  # Get additional claims from the token
    role = claims.get("role")  # Extract role information

    if role == "admin":
        admin = Admin.query.get(current_id)
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404
        return jsonify({'role': 'admin', 'message': 'Admin Validated'}), 200

    elif role == "user":
        user = User.query.get(current_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'role': 'user', 'message': 'User Validated'}), 200

    return jsonify({'error': 'Invalid token'}), 400

@app.route('/users', methods=['GET'])
def getAllUsers():
    users = User.query.all()  # Fetch all users from the database
    users_list = [
        {"id": user.id, "empid": user.empid, "email": user.email, "password": user.password,
         "geography": user.geography,
         "accountName": user.accountName, "transportData": user.transportData, "emissionData": user.emissionData}
        for user in users
    ]  # Convert each user object to a dictionary
    return jsonify(users_list)  # Return the list of users as JSON

@app.route('/settings', methods=['POST'])
@jwt_required()
def settings():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    data = request.json
    user.geography = data.get('geography')
    user.operatingCountry = data.get('operatingCountry')
    user.officeCity = data.get('officeCity')
    user.baseLocation = data.get('baseLocation')
    user.accountName = data.get('accountName')
    user.projectName = data.get('projectName')
    db.session.commit()
    return jsonify({
        'user': {
            'id': user.id,
            'name': user.name,
            'empid': user.empid,
            'geography': user.geography,
            'operatingCountry': user.operatingCountry,
            'baseLocation': user.baseLocation
        }
    }), 200

@app.route('/add-emission', methods=['POST'])
@jwt_required()
def addEmission():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.json
    transportData = data.get('transportData')
    user.numberOfDays = data.get('numberOfDays')

    now = datetime.now()
    if isinstance(transportData, dict):  # If single entry is received
        transportData = [transportData]
    formatted_transport_data = []

    for entry in transportData:
        formatted_transport_data.append({
            'month': now.month,
            'year': now.year,
            'distance': entry['distance'],
            'fuel': entry['fuel'],
            'mode': entry['mode']
        })
    user.transportData = user.transportData + formatted_transport_data

    emission = calculate_emission(user)
    # Ensure emissionData is a list before appending
    if not isinstance(user.emissionData, list):
        user.emissionData = []
    new_emission_entry = {
        'month': datetime.now().month,
        'year': datetime.now().year,
        'emission': emission
    }
    updated_emission_data = user.emissionData + [new_emission_entry]  # Create a new list
    user.emissionData = updated_emission_data  # Assign updated list
    db.session.commit()
    return jsonify({
        'user': {
            'id': user.id,
            'name': user.name,
            'empid': user.empid,
            'emissionData': user.emissionData
        }
    }), 200

def calculate_emission(user):
    ef_bus = 0.12999
    ef_motorbike = 0.10107
    ef_train = 0.03546
    ef_car_diesel = 0.16807
    ef_car_petrol = 0.17726
    ef_car_cng = 0.15682
    ef_car_hybrid = 0.1149
    emission = 0

    for data in user.transportData:
        mode = data['mode']
        fuel = data['fuel']
        distance = float(data['distance']) if data['distance'] else 0.0
        days = int(user.numberOfDays)
        ef = 0

        if mode == 'Bus':
            ef = ef_bus
        elif mode == 'Motorbike':
            ef = ef_motorbike
        elif mode == 'Train':
            ef = ef_train
        elif mode == 'Car':
            if fuel == 'Diesel':
                ef = ef_car_diesel
            elif fuel == 'CNG':
                ef = ef_car_cng
            elif fuel == 'Petrol':
                ef = ef_car_petrol
            elif fuel == 'Hybrid':
                ef = ef_car_hybrid

        emission += (ef * distance * days) / 1000

    return emission

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'user': {
            'id': user.id,
            'name': user.name,
            'empid': user.empid,
            'email': user.email,
            'transportData': user.transportData,
            'emissionData': user.emissionData,
            'geography': user.geography,
            'operatingCountry': user.operatingCountry,
            'baseLocation': user.baseLocation
        }
    }), 200

@app.route('/account-dashboard/<account_name>', methods=['GET'])
@jwt_required()
def accountDashboard(account_name):
    current_admin_id = get_jwt_identity()
    admin = Admin.query.get(current_admin_id)
    if not admin:
        return jsonify({'error': 'Admin not found'}), 404
    users = User.query.filter_by(accountName=account_name).all()
    if not users:
        return jsonify({'message': 'No users found for this account'}), 404
    # Convert query results to JSON format
    user_list = [{
        "id": user.id,
        "name": user.name,
        "empid": user.empid,
        "email": user.email,
        "geography": user.geography,
        "operatingCountry": user.operatingCountry,
        "officeCity": user.officeCity,
        "baseLocation": user.baseLocation,
        "accountName": user.accountName,
        "projectName": user.projectName,
        "transportData": user.transportData,
        "numberOfDays": user.numberOfDays,
        "emissionData": user.emissionData
    } for user in users]

    unique_project={} # for unique people in the account -- kpi1
    projectwise_distance={} # project wise distance travelld -- kpi2
    projectwise_emission={} # project wise emmission trend -- kpi3
    modewise_emission={} # mode wise emission trend -- kpi4
    modewise_distance={} # mode wise distance travelled --kpi5
    monthwise_emission={} # month wise emission trend --kpi6
    for user in user_list:
        total_distance=0
        #distance travlled by each user
        for data in user.get('transportData'):
            total_distance+=int(data.get('distance'))
        total_distance=total_distance*user.get('numberOfDays')

        if user.get('projectName') in unique_project :
            unique_project[user.get('projectName')]+=1  #--kpi1
            projectwise_distance[user.get('projectName')]+=total_distance #--kpi2
        else:
            unique_project[user.get('projectName')]=1
            projectwise_distance[user.get('projectName')]=total_distance

        # ---kpi3
        total_emmission=0   
        for data in user.get('emissionData'):
            total_emmission+=data.get('emission')

        if user.get('projectName') in projectwise_emission:
            projectwise_emission[user.get('projectName')]+=total_emmission
        else:
            projectwise_emission[user.get('projectName')]=total_emmission

        # ---kpi4
        for data in user.get('transportData'):
            ef_bus = 0.12999
            ef_motorbike = 0.10107
            ef_train = 0.03546
            ef_car_diesel = 0.16807
            ef_car_petrol = 0.17726
            ef_car_cng = 0.15682
            ef_car_hybrid = 0.1149
            emission = 0
            mode = data.get('mode')
            fuel = data.get('fuel')
            distance = float(data.get('distance')) if data.get('distance') else 0.0
            days = int(user.get('numberOfDays'))
            ef = 0
            if mode == 'Bus':
                ef = ef_bus
            elif mode == 'Motorbike':
                ef = ef_motorbike
            elif mode == 'Train':
                ef = ef_train
            elif mode == 'Car':
                if fuel == 'Diesel':
                    ef = ef_car_diesel
                elif fuel == 'CNG':
                    ef = ef_car_cng
                elif fuel == 'Petrol':
                    ef = ef_car_petrol
                elif fuel == 'Hybrid':
                    ef = ef_car_hybrid


            if mode in modewise_emission:
                modewise_emission[data.get('mode')]+=((ef*distance*days)/1000)
            else:
                modewise_emission[data.get('mode')]=((ef*distance*days)/1000)

        # ---kpi5
        for data in user.get('transportData'):
            if data.get('mode') in modewise_distance:
                modewise_distance[data.get('mode')]+=user.get('numberOfDays')*int(data.get('distance'))
            else:
                modewise_distance[data.get('mode')]=user.get('numberOfDays')*int(data.get('distance'))

        # ---kpi6

        for data in user.get('emissionData'):
            if data.get('month') in monthwise_emission:
                monthwise_emission[data.get('month')]+=data.get('emission')
            else :
                monthwise_emission[data.get('month')]=data.get('emission')



    return jsonify({'status': 'success', 'users': user_list,'kpi1':[unique_project],'kpi2':[projectwise_distance],'kpi3':[projectwise_emission],'kpi4':[modewise_emission],'kpi5':[modewise_distance],'kpi6':[monthwise_emission]}), 200

if __name__ == '__main__':
    app.run(debug=True)