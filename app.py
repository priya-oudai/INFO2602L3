from flask import Flask, jsonify, request
from functools import wraps
from flask_cors import CORS
#import integriy error
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
)

from models import Admin, Category, RegularUser, Todo, TodoCategory, db, User

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'MySecretKey'
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token'
app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config['JWT_COOKIE_SAMESITE'] = 'None'

db.init_app(app)
CORS(app)
app.app_context().push()

jwt = JWTManager(app)


# customn decorator authorize routes for admin or regular user
def login_required(required_class):
  def wrapper(f):
    @wraps(f)
    @jwt_required()  # Ensure JWT authentication
    def decorated_function(*args, **kwargs):
      user = required_class.query.filter_by(
          username=get_jwt_identity()).first()
      if user.__class__ != required_class:  # Check class equality
        return jsonify(error='Invalid user role'), 403
      return f(*args, **kwargs)
    return decorated_function
  return wrapper


def login_user(username, password):
  user = User.query.filter_by(username=username).first()
  if user and user.check_password(password):
    token = create_access_token(identity=username)
    response = jsonify(access_token=token)
    set_access_cookies(response, token)
    return response
  return jsonify(error="Invalid username or password"), 401


@app.route('/')
def index():
  return '<h1>mY Todo API</h1>'


# Login
@app.route('/login', methods=['POST'])
def user_login_view():
  data = request.json
  return login_user(data['username'], data['password'])


@app.route('/identify')
@jwt_required()
def identify_view():
  username = get_jwt_identity()
  user = User.query.filter_by(username=username).first()
  if user:
    return jsonify(user.get_json())
  return jsonify(message='Invalid user'), 403


# Sign Up
@app.route('/signup', methods=['POST'])
def signup_user_view():
  data = request.json
  try:
    new_user = RegularUser(data['username'], data['email'], data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify(
        message=f'User {new_user.id} - {new_user.username} created!'), 201
  except IntegrityError:
    db.session.rollback()
    return jsonify(error='Username already exists'), 400


# Logout
@app.route('/logout', methods=['GET'])
def logout():
  response = jsonify(message='Logged out')
  unset_jwt_cookies(response)
  return response


# Todo Crud Operations

@app.route('/todos', methods=['POST'])
@login_required(RegularUser)
def create_todo_view():
  data = request.json
  username = get_jwt_identity()
  user = RegularUser.query.filter_by(username=username).first()
  new_todo = user.add_todo(data['text'])
  return jsonify(message=f'todo {new_todo.id} created!'), 201


@app.route('/todos', methods=['GET'])
@login_required(RegularUser)
def get_todos_view():
  # get the user object of the authenticated user
  user = RegularUser.query.filter_by(username=get_jwt_identity()).first()
  # converts todo objects to list of todo dictionaries
  todo_json = [todo.get_json() for todo in user.todos]
  todo_json.reverse()
  return jsonify(todo_json), 200


@app.route('/todos/<int:id>', methods=['GET'])
@login_required(RegularUser)
def get_todo_view(id):
  todo = Todo.query.get(id)

  # must check if todo belongs to the authenticated user
  if not todo or todo.user.username != get_jwt_identity():
    return jsonify(error="Bad ID or unauthorized"), 401

  return jsonify(todo.get_json()), 200


@app.route('/todos/<int:id>', methods=['PUT'])
@login_required(RegularUser)
def edit_todo_view(id):
  data = request.json
  user = RegularUser.query.filter_by(username=get_jwt_identity()).first()

  todo = Todo.query.get(id)

  # must check if todo belongs to the authenticated user
  if not todo or todo.user.username != get_jwt_identity():
    return jsonify(error="Bad ID or unauthorized"), 401

  user.update_todo(id, data['text'])
  return jsonify(message=f"todo updated to '{data['text']}'!"), 200

@app.route('/todos/<int:id>/done', methods=['PUT'])
@login_required(RegularUser)
def toggle_todo_view(id):
  user = RegularUser.query.filter_by(username=get_jwt_identity()).first()

  todo = Todo.query.get(id)

  # must check if todo belongs to the authenticated user
  if not todo or todo.user.username != get_jwt_identity():
    return jsonify(error="Bad ID or unauthorized"), 401

  todo = user.toggle_todo(id)
  return jsonify(message=f"todo {'done' if todo.done else 'not done'}!"), 200

@app.route('/todos/<int:id>', methods=['DELETE'])
@login_required(RegularUser)
def delete_todo_view(id):
  user = RegularUser.query.filter_by(username=get_jwt_identity()).first()
  todo = Todo.query.get(id)

  # must check if todo belongs to the authenticated user
  if not todo or todo.user.username != get_jwt_identity():
    return jsonify(error="Bad ID or unauthorized"), 401

  user.delete_todo(id)
  return jsonify(message="todo deleted!"), 200


@app.route('/todos/stats', methods=['GET'])
@login_required(RegularUser)
def get_stats_view():
  user = RegularUser.query.filter_by(username=get_jwt_identity()).first()
  return jsonify(num_todos=user.getNumTodos(),
                 num_done=user.getDoneTodos()), 200


if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True)

