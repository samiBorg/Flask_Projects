from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required, get_jwt
from sqlalchemy.exc import SQLAlchemyError

from db import db
from models import TaskModel
from schemas import TaskSchema, TaskUpdateSchema

blp = Blueprint("Tasks", "task", description="Operations on task")


@blp.route("/task/<string:task_id>")
@cache.cached(timeout=30, query_string=True)
class Task(MethodView):
    @jwt_required()
    @blp.response(200, TaskSchema)
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

    @blp.arguments(TaskUpdateSchema)
    @blp.response(200, TaskSchema)
    def put(self, task_data, task_id):
        task = TaskModel.query.get(task_id)

        if task:
            task.status = task_data["status"]
            
        else:
            task = TaskModel(id=task_id, **task_data)

        db.session.add(task)
        db.session.commit()

        return task


@blp.route("/task")
@cache.cached(timeout=30, query_string=True)
class TaskList(MethodView):
    @jwt_required()
    @blp.response(200, TaskSchema(many=True))
    def get(self):
        return TaskModel.query.all()

    @jwt_required(fresh=True)
    @blp.arguments(TaskSchema)
    @blp.response(201, TaskSchema)
    def post(self, task_data):
        task = TaskModel(**task_data)

        try:
            db.session.add(task)
            db.session.commit()
        except SQLAlchemyError:
            abort(500, message="An error occurred while inserting the task.")

        return task