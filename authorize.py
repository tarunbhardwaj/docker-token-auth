import os
import yaml

config = yaml.load(open(os.environ['AUTH_CONFIG']).read())


class Auth():
    def check_access(cls, username, password, scope):
        "Check if username, password and scope combination is allowed"
        if not cls.authenticate_user(username, password):
            return False
        if not scope:
            # Login call
            return True
        if username in config.get('admins', {}):
            return True  # every scope is allowed
        if scope.actions in config.get('images', {}) \
                .get(scope.image, {}) \
                .get('user', {}) \
                .get(username, []):
            return True
        return False

    def authenticate_user(cls, username, password):
        "authenticate username and password from config file"
        if username not in config.get('users', {}):
            return False
        if config['users'][username] != password:
            return False
        return True
