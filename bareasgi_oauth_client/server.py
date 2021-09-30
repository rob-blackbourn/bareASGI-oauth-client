"""Server"""

import asyncio

from hypercorn.asyncio import serve
from hypercorn.config import Config

from bareasgi_oauth_client.app import make_application


def start_server():
    app = make_application()

    config = Config()
    config.bind = ["localhost:5000"]
    asyncio.run(serve(app, config))  # type: ignore


if __name__ == '__main__':
    start_server()
