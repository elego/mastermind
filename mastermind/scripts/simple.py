from __future__ import (absolute_import, print_function, division)

import sys
import mitmproxy
from mitmproxy import ctx


def response(flow: mitmproxy.http.HTTPFlow) -> None:
    if flow.request.url == ctx.url:
        flow.request.headers['Cache-Control'] = 'no-cache'
        flow.response.headers['Cache-Control'] = 'no-cache'

        if 'If-None-Match' in flow.request.headers:
            del flow.request.headers['If-None-Match']
        if 'ETag' in flow.response.headers:
            del flow.response.headers['ETag']

        data = open(ctx.response_body).read()
        flow.response.content = data


def load(loader):
    ctx.log.info("Registering option 'url'")
    loader.add_option(
        "url", str, "", "A URL to mock its response",
    )
    ctx.log.info("Registering option 'response_body'")
    loader.add_option(
        "response_body", str, "", (
            "A file containing the mocked response body"
        )
    )


def configure(updated):
    if "url" in updated:
        ctx.log.info("url value: %s" % ctx.options.url)
    if "response_body" in updated:
        ctx.log.info("response_body value: %s" % ctx.options.response_body)
