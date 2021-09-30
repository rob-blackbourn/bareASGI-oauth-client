"""Oauth Client Controller"""

from secrets import token_urlsafe
from urllib.parse import parse_qs, urlencode

from bareasgi import Application, HttpRequest, HttpResponse
from bareutils import response_code
from bareutils.streaming import text_writer, text_reader
from bareclient import HttpClient

SESSION = {}


class OAuthClientController:

    def __init__(
            self,
            path_prefix: str,
            client_id: str,
            client_secret: str,
            authorization_base_url: str,
            token_url: str
    ) -> None:
        self.path_prefix = path_prefix
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_base_url = authorization_base_url
        self.token_url = token_url

    def add_routes(self, app: Application) -> Application:
        app.http_router.add(
            {'GET'},
            self.path_prefix + '/',
            self.request_authorization
        )
        app.http_router.add(
            {'GET'},
            self.path_prefix + '/callback',
            self.oauth_server_callback
        )
        app.http_router.add(
            {'GET'},
            self.path_prefix + '/profile',
            self.oauth_server_profile
        )
        return app

    async def request_authorization(self, _request: HttpRequest) -> HttpResponse:
        state = token_urlsafe(32)
        SESSION['oauth_state'] = state
        location = self.authorization_base_url + '?' + urlencode(
            (
                ('client_id', self.client_id),
                ('state', state)
            )
        )
        headers = [(b'location', location.encode())]
        return HttpResponse(
            response_code.FOUND,
            headers
        )

    async def oauth_server_callback(self, request: HttpRequest) -> HttpResponse:
        state = SESSION['oauth_state']
        params = {
            name.decode(): values[0].decode()
            for name, values in parse_qs(request.scope['query_string']).items()
        }
        assert params['state'] == state
        headers = [
            (b'content-type', b'application/x-www-form-urlencoded')
        ]
        body = urlencode([
            ('client_id', self.client_id),
            ('client_secret', self.client_secret),
            ('code', params['code'])
        ])

        async with HttpClient(
            self.token_url,
            method='POST',
            headers=headers,
            body=text_writer(body)
        ) as oauth_response:
            assert oauth_response.body is not None
            oauth_body = await text_reader(oauth_response.body)
            results = parse_qs(oauth_body)
            print(results)

            # At this point you can fetch protected resources but lets save
            # the token and show how this is done from a persisted token
            # in /profile.
            SESSION['oauth_token'] = results['access_token'][0]
            SESSION['oauth_token_type'] = results['token_type'][0]

        location = self.path_prefix + '/profile'

        headers = [(b'location', location.encode())]
        return HttpResponse(
            response_code.FOUND,
            headers
        )

    async def oauth_server_profile(self, _request: HttpRequest) -> HttpResponse:
        token = SESSION['oauth_token']
        headers = [
            (b'authorization', f"token {token}".encode())
        ]
        async with HttpClient(
            'https://api.github.com/user',
            headers=headers
        ) as oauth_response:
            assert oauth_response.body is not None
            oauth_body = await text_reader(oauth_response.body)
            print(oauth_body)

        return HttpResponse(
            200,
            [(b'content-type', b'application/json')],
            text_writer(oauth_body)
        )
