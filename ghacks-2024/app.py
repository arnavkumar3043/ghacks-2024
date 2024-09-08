from functools import wraps
from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response
from util.database import signup, login, createOfficeHour, get_db_connection
from datetime import datetime
import jwt

app = Flask(__name__)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect('/auth')  # Redirect to auth page if token is missing
        
        try:
            data = jwt.decode(token, 'officehours', algorithms=['HS256'])
            email = data['email']
            role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 403
        
        return f(email=email, role=role, *args, **kwargs)
    
    return decorated

@app.route('/')
@token_required
def home(email, role):
    if role == 'professor':
        return redirect('/profdashboard')
    
    connection = get_db_connection()
    cursor = connection.cursor()

    # Fetch the profs and classes column for the current user
    cursor.execute('SELECT profs FROM users WHERE email = ?', (email,))
    user_profs = cursor.fetchone()[0]
    user_profs_list = user_profs.split(',') if user_profs else []

    # Fetch all professors and their classes
    cursor.execute('''
        SELECT u.id, u.name, u.email, GROUP_CONCAT(o.class) 
        FROM users u 
        LEFT JOIN officehours o ON u.email = o.prof_email 
        WHERE u.role = "professor" 
        GROUP BY u.id, u.name, u.email
    ''')
    professors = cursor.fetchall()

    connection.close()

    return render_template('index.html', professors=professors, user_profs_list=user_profs_list)


@app.route('/officehours')
@token_required
def office(email, role):
    if role == 'professor':
        return redirect('/profdashboard')

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute('SELECT profs FROM users WHERE email = ?', (email,))
    user_profs = cursor.fetchone()[0]
    user_profs_list = user_profs.split(',') if user_profs else []

    cursor.execute('''
        SELECT officehours.class, officehours.datetime, officehours.questions, officehours.location, officehours.prof_email, users.name, officehours.id
        FROM officehours
        JOIN users ON officehours.prof_email = users.email
        WHERE (officehours.prof_email || "#" || officehours.class) IN ({seq})
    '''.format(seq=','.join(['?']*len(user_profs_list))), user_profs_list)
    
    office_hours = cursor.fetchall()

    formatted_office_hours = []
    for office_hour in office_hours:
        dt = datetime.strptime(office_hour[1], '%Y-%m-%dT%H:%M')
        formatted_datetime = dt.strftime('%B %d, %Y at %I:%M %p')
        question_ids = office_hour[2].split(',') if office_hour[2] else []
        questions = []
        if question_ids:
            cursor.execute('SELECT id, description, votes, voted_by FROM questions WHERE id IN ({seq})'.format(seq=','.join(['?']*len(question_ids))), question_ids)
            for row in cursor.fetchall():
                question_id = row[0]
                description = row[1]
                votes = row[2]
                voted_by = row[3].split(',') if row[3] else []
                has_voted = email in voted_by
                questions.append((description, votes, question_id, has_voted))

        formatted_office_hours.append((office_hour[0], formatted_datetime, questions, office_hour[3], office_hour[4], office_hour[5], office_hour[6]))

    connection.close()

    return render_template('officehours.html', office_hours=formatted_office_hours)


@app.route('/profhours')
@token_required
def myHours(email, role):
    if role == 'student':
        return redirect('/')
    
    connection = get_db_connection()
    cursor = connection.cursor()

    # Fetch the professor's office hours
    cursor.execute('''
        SELECT officehours.class, officehours.datetime, officehours.questions, officehours.location, officehours.prof_email, officehours.id
        FROM officehours
        WHERE officehours.prof_email = ?
    ''', (email,))
    office_hours = cursor.fetchall()

    formatted_office_hours = []
    for office_hour in office_hours:
        dt = datetime.strptime(office_hour[1], '%Y-%m-%dT%H:%M')
        formatted_datetime = dt.strftime('%B %d, %Y at %I:%M %p')
        question_ids = office_hour[2].split(',') if office_hour[2] else []
        questions = []
        if question_ids:
            cursor.execute('SELECT id, description, votes FROM questions WHERE id IN ({seq})'.format(seq=','.join(['?']*len(question_ids))), question_ids)
            for row in cursor.fetchall():
                question_id = row[0]
                description = row[1]
                votes = row[2]
                questions.append((description, votes, question_id))

        formatted_office_hours.append((office_hour[0], formatted_datetime, questions, office_hour[3], office_hour[4], office_hour[5]))

    connection.close()

    return render_template('profHours.html', office_hours=formatted_office_hours)


@app.route('/profdashboard')
@token_required
def profdashboard(email, role):
    if role == 'student':
        return redirect('/')

    return render_template('profDashboard.html')


@app.route('/auth')
def authenticateUI():
    return render_template('authorize.html')

@app.route('/signup', methods=['POST'])
def handle_signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    role = data.get('role')
    password = data.get('password')
    
    # Call the signup function
    status, token = signup(name, email, role, password)
    
    response = make_response(jsonify(success=status, token=token))
    if status:
        response.set_cookie('token', token, httponly=True, secure=True)
    # Return the result as JSON
    return response

@app.route('/login', methods=['POST'])
def handle_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    # Call the login function
    status, token = login(email, password)
    
    response = make_response(jsonify(success=True, token=token))
    if status:
        response.set_cookie('token', token, httponly=True, secure=True, samesite='Strict')
        return response
    else:
        return jsonify(success=False)
    
@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect(url_for('home')))
    response.set_cookie('token', '', expires=0)  # Clear the token cookie
    return response


@app.route('/createofficehour', methods=['POST'])
@token_required
def create_officehour(email, role):
    data = request.get_json()
    datetime1 = data.get('datetime')
    lec = data.get('lecture')
    questions = ""
    prof_email = email
    location = data.get('location')

    createOfficeHour(datetime1, lec, questions, prof_email, location)
    return jsonify({'message': 'Office hour successfully inserted.'})

@app.route('/enrollprof', methods=['POST'])
@token_required
def enroll_prof(email, role):
    data = request.get_json()
    prof_email = data.get('prof_email')
    class_name = data.get('class_name')
    prof_class = f"{prof_email}#{class_name}"

    connection = get_db_connection()
    cursor = connection.cursor()

    # Fetch the current profs column for the user
    cursor.execute('SELECT profs FROM users WHERE email = ?', (email,))
    user_profs = cursor.fetchone()[0]
    user_profs_list = user_profs.split(',') if user_profs else []

    # Append the new professor-class combination if not already enrolled
    if prof_class not in user_profs_list:
        user_profs_list.append(prof_class)
        new_profs = ','.join(user_profs_list)
        cursor.execute('UPDATE users SET profs = ? WHERE email = ?', (new_profs, email))
        connection.commit()

    connection.close()

    return jsonify({'message': 'Successfully enrolled in the professor\'s class.'})


@app.route('/askquestion', methods=['POST'])
@token_required
def ask_question(email, role):
    data = request.get_json()
    question = data.get('question')
    officehour_id = data.get('officehour_id')

    connection = get_db_connection()
    cursor = connection.cursor()

    # Insert the question into the questions table
    cursor.execute('INSERT INTO questions (description, user_email) VALUES (?, ?)', (question, email))
    question_id = cursor.lastrowid

    # Fetch the current questions for the office hour
    cursor.execute('SELECT questions FROM officehours WHERE id = ?', (officehour_id,))
    current_questions = cursor.fetchone()[0]
    current_questions_list = current_questions.split(',') if current_questions else []

    # Append the new question ID
    current_questions_list.append(str(question_id))
    new_questions = ','.join(current_questions_list)

    # Update the officehours table with the new questions list
    cursor.execute('UPDATE officehours SET questions = ? WHERE id = ?', (new_questions, officehour_id))
    connection.commit()
    connection.close()

    return jsonify({'message': 'Question successfully added.'})

@app.route('/upvote', methods=['POST'])
@token_required
def upvote_question(email, role):
    data = request.get_json()
    question_id = data.get('question_id')

    connection = get_db_connection()
    cursor = connection.cursor()

    # Check if the user has already voted for this question
    cursor.execute('SELECT voted_by, votes FROM questions WHERE id = ?', (question_id,))
    row = cursor.fetchone()
    if row is None:
        return jsonify({'message': 'Question not found.'}), 404

    voted_by = row[0].split(',') if row[0] else []
    votes = row[1]

    if email in voted_by:
        return jsonify({'message': 'You have already voted for this question.'}), 400

    # Update the votes and voted_by
    voted_by.append(email)
    new_votes = votes + 1
    new_voted_by = ','.join(voted_by)
    cursor.execute('UPDATE questions SET votes = ?, voted_by = ? WHERE id = ?', (new_votes, new_voted_by, question_id))

    connection.commit()
    connection.close()

    return jsonify({'message': 'Vote recorded successfully.', 'new_votes': new_votes})

if __name__ == '__main__':
    app.run(debug=True)
