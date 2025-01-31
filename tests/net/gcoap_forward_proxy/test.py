#!/usr/bin/env -S pipx run
# /// script
# dependencies = [
#   "aiocoap == 0.4.11",
# ]
# ///

import sys
import asyncio
import logging

import aiocoap
from aiocoap.resource import Resource, Site

# monkey patch token manager to see the impact of different token lengths … but
# really, the proxy reuses the token.
aiocoap.tokenmanager.TokenManager.next_token = lambda self: b""

class Canary(Resource):
    def __init__(self):
        self.count = 0

    async def render_post(self, request):
        self.count += 1
        # Pushing the limit in the response
        return aiocoap.Message(payload=b"x"*123)

async def run_test(remote: str, proxy_uri: str):
    root = Site()

    canary = Canary()

    root.add_resource(["canary"], canary)

    ctx = await aiocoap.Context.create_server_context(root, bind=("::", 9876))

    # No point in pushing the request message limit: there the token is the
    # same length but the Proxy-Uri option is replaced with the more compact
    # Uri-Path option
    request = aiocoap.Message(uri=remote, code=aiocoap.POST)
    request.opt.proxy_uri = proxy_uri
    response = await ctx.request(request).response_raising
    if canary.count == 0:
        raise RuntimeError("The proxy cheated.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # Going off the default port and using a multicast address conveniently
    # avoids the need to know the own address, especially when the peer may
    # need to have a zone identifier on it, which is not really supposed to be
    # proxied that way.
    asyncio.run(run_test(sys.argv[1], "coap://[ff02::1]:9876/canary"))
