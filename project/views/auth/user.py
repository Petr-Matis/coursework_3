from flask import request
from flask_restx import Namespace, Resource
from project.container import user_service
from project.setup.api.models import user
from project.tools.security import auth_required


api = Namespace('user')


@api.route('/')
class UserView(Resource):
    @api.marshal_with(user, as_list=True, code=200, description='OK')
    @auth_required
    def get(self):
        """
        Get user.
        """
        return user_service.get_all()

    @api.marshal_with(user, as_list=True, code=200, description='OK')
    @auth_required
    def patch(self):
        """
        Updat users.
        """
        token = request.headers["Authorization"].split("Bearer")[-1].strip()
        data = request.json
        return user_service.update_user(data=data, token=token)


@api.route('/password')
class PasswordView(Resource):
    @api.marshal_with(user, as_list=True, code=200, description='OK')
    @auth_required
    def put(self):
        """
        Update password
        """
        data = request.json
        token = request.headers["Authorization"].split("Bearer")[-1].strip()
        return user_service.update_password(data=data, token=token)
