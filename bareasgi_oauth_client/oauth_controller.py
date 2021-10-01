"""Oauth Client Controller"""

from secrets import token_urlsafe, compare_digest
from typing import Any, Dict, Sequence, Tuple
from urllib.parse import parse_qs, urlencode

from bareasgi import Application, HttpRequest, HttpResponse
from bareasgi_session import session_data
from bareutils import response_code, text_writer, text_reader
from bareclient import HttpClient


def _make_redirect_response(
        url: str,
        params: Sequence[Tuple[str, str]]
) -> HttpResponse:
    location = url + '?' + urlencode(params)
    headers = [(b'location', location.encode())]
    return HttpResponse(
        response_code.FOUND,
        headers
    )


def _unpack_unique_query_string(query_string: bytes) -> Dict[str, Any]:
    return {
        name.decode(): values[0].decode()
        for name, values in parse_qs(query_string).items()
    }


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

    async def request_authorization(self, request: HttpRequest) -> HttpResponse:
        state = token_urlsafe(32)
        session = session_data(request)
        session['oauth_state'] = state
        params = (
            ('client_id', self.client_id),
            ('state', state)
        )
        return _make_redirect_response(self.authorization_base_url, params)

    async def oauth_server_callback(self, request: HttpRequest) -> HttpResponse:
        session = session_data(request)
        state = session['oauth_state']
        params = _unpack_unique_query_string(request.scope['query_string'])
        if not compare_digest(params['state'], state):
            return HttpResponse(response_code.FORBIDDEN)

        token, token_type = await self._request_access_token(params['code'])

        session['oauth_token'] = token
        session['oauth_token_type'] = token_type

        location = self.path_prefix + '/profile'

        headers = [(b'location', location.encode())]
        return HttpResponse(
            response_code.FOUND,
            headers
        )

    async def _request_access_token(
            self,
            code: str
    ) -> Tuple[str, str]:
        headers = [
            (b'content-type', b'application/x-www-form-urlencoded')
        ]
        body = urlencode([
            ('client_id', self.client_id),
            ('client_secret', self.client_secret),
            ('code', code)
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
            return results['access_token'][0], results['token_type'][0]

    async def oauth_server_profile(self, request: HttpRequest) -> HttpResponse:
        session = session_data(request)
        token = session['oauth_token']
        user_profile = await self._request_github_user_profile(token)

        return HttpResponse(
            200,
            [(b'content-type', b'application/json')],
            text_writer(user_profile)
        )

    async def _request_github_user_profile(self, token: str) -> str:
        headers = [
            (b'authorization', f"token {token}".encode())
        ]
        async with HttpClient(
            'https://api.github.com/user',
            headers=headers
        ) as oauth_response:
            assert oauth_response.body is not None
            return await text_reader(oauth_response.body)
