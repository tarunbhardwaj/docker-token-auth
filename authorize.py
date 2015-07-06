import os
import yaml

config = yaml.load(open(os.environ['AUTH_CONFIG']).read())


class Auth():
    def check_access(cls, username, password, scope):
        if not cls.authenticate_user(username, password):
            return False
        if username in config.get('admins', {}):
            return True  # every scope is allowed
        if scope.action in config.get('images', {}) \
            .get(scope.image, {}) \
            .get('user', {}) \
            .get(username, []):
            return True
        return False

    def authenticate_user(cls, username, password):
        if username not in config.get('users', {}):
            return False
        if config['users'][username] != password:
            return False
        return True
