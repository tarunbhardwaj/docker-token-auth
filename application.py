import json
from collections import namedtuple

from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, NotFound, abort

from jwt_token import JWTToken
from authorize import Auth

Scope = namedtuple('Scope', ['type', 'image', 'action'])


class DockerAuth(object):
    def __init__(self):
        self.url_map = Map([
            Rule('/v2/token/', endpoint='authorize'),
        ])

    def on_authorize(self, request):
        scope = \
            request.args.get('scope') and request.args.get('scope').split(':')
        if not request.authorization:
            abort(401)
        if not Auth().check_access(
            request.authorization.username,
            request.authorization.password,
            scope
        ):
            abort(401)
        token = JWTToken(
            request.args['account'], request.args['service'],
            scope
        ).generate()
        res = {
            'token': token
        }
        return Response(json.dumps(res))

    def dispatch_request(self, request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            return getattr(self, 'on_' + endpoint)(request, **values)
        except NotFound, e:
            return abort(404)
        except HTTPException, e:
            return e

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


if __name__ == '__main__':
    from werkzeug.serving import run_simple
    app = DockerAuth()
    run_simple('0.0.0.0', 4567, app, use_debugger=True, use_reloader=True)
