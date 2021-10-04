"""The ASGI Application"""

import os

from bareasgi import Application
from bareasgi_session import add_session_middleware

from .github_oauth_controller import GitHubOAuthClientController
from .google_oauth_controller import GoogleOAuthClientController


def make_application() -> Application:

    app = Application()

    add_session_middleware(app)

    # # GitHub
    # controller = GithubOAuthClientController(
    #     '',
    #     os.environ['GITHUB_CLIENT_ID'],
    #     os.environ['GITHUB_CLIENT_SECRET'],
    #     'https://github.com/login/oauth/authorize',
    #     'https://github.com/login/oauth/access_token',
    #     [],
    #     'https://api.github.com/user'
    # )

    # Google
    controller = GoogleOAuthClientController(
        '',
        os.environ['GOOGLE_CLIENT_ID'],
        os.environ['GOOGLE_CLIENT_SECRET'],
        'https://accounts.google.com/o/oauth2/v2/auth',
        'https://www.googleapis.com/oauth2/v4/token',
        [
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
            "https://www.googleapis.com/auth/userinfo.profile"
        ],
        'https://www.googleapis.com/oauth2/v1/userinfo'
    )

    controller.add_routes(app)

    return app
