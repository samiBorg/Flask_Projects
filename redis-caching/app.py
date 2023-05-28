from flask import Flask, request, jsonify
import requests
import redis

from flask_caching import Cache

####user
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_jwt,
    jwt_required,
)
from passlib.hash import pbkdf2_sha256

from db import db
from models.user import UserModel
from schemas import UserSchema
from blocklist import BLOCKLIST

######tasks
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required, get_jwt
from sqlalchemy.exc import SQLAlchemyError

from db import db
from models.task import TaskModel
from schemas import TaskSchema, TaskUpdateSchema

####
import os
from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager

from db import db
from blocklist import BLOCKLIST


def create_app(db_url=None):
    app = Flask(__name__)
    
    app.config.from_object("config")

    app.config["CACHE_TYPE"] = "RedisCache"
    # app.config["CACHE_REDIS_HOST"] = "localhost"
    # app.config["CACHE_REDIS_PORT"] = 6379
    # app.config["CACHE_REDIS_URL"] = "redis://localhost:6379"

    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Stores REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"


    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL", "sqlite:///data.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = True
    db.init_app(app)
    #db.create_all()

    cache = Cache(app)

    db_cache = redis.Redis(host="redis_container", port=6379, decode_responses=True)
    # db.init_app(app)
    api = Api(app)

    app.config["JWT_SECRET_KEY"] = "jose"
    jwt = JWTManager(app)


    # @app.route("/todo")
    # @cache.cached(timeout=3000, query_string=True)
    # def get_task():
    #     API_URL = "http://universities.hipolabs.com/search?country="
    #     search = request.args.get("country")
    #     r = requests.get(f"{API_URL}{search}")
    #     return jsonify(r.json())

        # return app

    ##user    
    blpu = Blueprint("Users", "users", description="Operations on users")

    @blpu.route("/register")
    class UserRegister(MethodView):
        @blpu.arguments(UserSchema)
        def post(self, user_data):
            if UserModel.query.filter(UserModel.username == user_data["username"]).first():
                abort(409, message="A user with that username already exists.")

            user = UserModel(
                username=user_data["username"],
                password=pbkdf2_sha256.hash(user_data["password"]),
            )
            db.session.add(user)
            db.session.commit()

            return {"message": "User created successfully."}, 201


    @blpu.route("/login")
    @cache.cached(timeout=3000, query_string=True)
    class UserLogin(MethodView):
        @blpu.arguments(UserSchema)
        def post(self, user_data):
            user = UserModel.query.filter(
                UserModel.username == user_data["username"]
            ).first()

            if user and pbkdf2_sha256.verify(user_data["password"], user.password):
                access_token = create_access_token(identity=user.id, fresh=True)
                refresh_token = create_refresh_token(user.id)
                return {"access_token": access_token, "refresh_token": refresh_token}, 200

            abort(401, message="Invalid credentials.")


    @blpu.route("/logout")
    class UserLogout(MethodView):
        @jwt_required()
        def post(self):
            jti = get_jwt()["jti"]
            BLOCKLIST.add(jti)
            return {"message": "Successfully logged out"}, 200


    @blpu.route("/user/<int:user_id>")
    class User(MethodView):
        """
        This resource can be useful when testing our Flask app.
        We may not want to expose it to public users, but for the
        sake of demonstration in this course, it can be useful
        when we are manipulating data regarding the users.
        """

        @blpu.response(200, UserSchema)
        def get(self, user_id):
            user = UserModel.query.get_or_404(user_id)
            return user

        def delete(self, user_id):
            user = UserModel.query.get_or_404(user_id)
            db.session.delete(user)
            db.session.commit()
            return {"message": "User deleted."}, 200


    @blpu.route("/refresh")
    class TokenRefresh(MethodView):
        @jwt_required(refresh=True)
        def post(self):
            current_user = get_jwt_identity()
            new_token = create_access_token(identity=current_user, fresh=False)
            # Make it clear that when to add the refresh token to the blocklist will depend on the app design
            jti = get_jwt()["jti"]
            BLOCKLIST.add(jti)
            return {"access_token": new_token}, 200



    ########tasks
    blpt= Blueprint("Tasks", "task", description="Operations on task")


    @blpt.route("/task/<string:task_id>")
    class Task(MethodView):
        @jwt_required()
        @blpt.response(200, TaskSchema)
        def get(self, task_id):
            task = TaskModel.query.get_or_404(task_id)
            return task

        @jwt_required()
        def delete(self, task_id):
            jwt = get_jwt()
            if not jwt.get("is_admin"):
                abort(401, message="Admin privilege required.")

            task = TaskModel.query.get_or_404(task_id)
            db.session.delete(task)
            db.session.commit()
            return {"message": "task deleted."}

        @blpt.arguments(TaskUpdateSchema)
        @blpt.response(200, TaskSchema)
        def put(self, task_data, task_id):
            task = TaskModel.query.get(task_id)

            if task:
                task.status = task_data["status"]
                
            else:
                task = TaskModel(id=task_id, **task_data)

            db.session.add(task)
            db.session.commit()

            return task


    @blpt.route("/task")
    class TaskList(MethodView):
        @jwt_required()
        @blpt.response(200, TaskSchema(many=True))
        def get(self):
            return TaskModel.query.all()

        @jwt_required(fresh=True)
        @blpt.arguments(TaskSchema)
        @blpt.response(201, TaskSchema)
        def post(self, task_data):
            task = TaskModel(**task_data)

            try:
                db.session.add(task)
                db.session.commit()
            except SQLAlchemyError:
                abort(500, message="An error occurred while inserting the task.")

            return task
        
    #######jwt settings

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload["jti"] in BLOCKLIST

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return (
            jsonify({"message": "The token has expired.", "error": "token_expired"}),
            401,
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify(
                {"message": "Signature verification failed.", "error": "invalid_token"}
            ),
            401,
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify(
                {
                    "description": "Request does not contain an access token.",
                    "error": "authorization_required",
                }
            ),
            401,
        )

    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {
                    "description": "The token is not fresh.",
                    "error": "fresh_token_required",
                }
            ),
            401,
        )

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {"description": "The token has been revoked.", "error": "token_revoked"}
            ),
            401,
        )

        # JWT configuration ends

        # with app.app_context():
        #     import models  # noqa: F401

        #     db.create_all()

        # api.register_blueprint(blpu)
        # api.register_blueprint(blpt)
    with app.app_context():
        import models  # noqa: F401

        db.create_all()

    api.register_blueprint(blpu)
    api.register_blueprint(blpt)


    return app



'''if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
'''
# from flask import Flask

# app = Flask(__name__)


# @app.route("/")
# def hello():
#     return "Hello World"


# if __name__ == "__main__":
#     app.run()
