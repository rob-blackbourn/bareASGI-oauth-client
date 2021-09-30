"""The ASGI Application"""

import os

from bareasgi import Application
from bareasgi_session import add_session_middleware

from .oauth_controller import OAuthClientController


def make_application() -> Application:

    app = Application()

    add_session_middleware(app)

    controller = OAuthClientController(
        '',
        os.environ['OAUTH_CLIENT_ID'],
        os.environ['OAUTH_CLIENT_SECRET'],
        'https://github.com/login/oauth/authorize',
        'https://github.com/login/oauth/access_token'
    )

    controller.add_routes(app)

    return app
