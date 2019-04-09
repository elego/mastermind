from __future__ import (absolute_import, print_function, division)

import sys
import mitmproxy 
from mitmproxy import ctx

from mastermind import (driver, handlers)


def request(flow: mitmproxy.http.HTTPFlow) -> None:
    handlers.request(flow)


def response(flow: mitmproxy.http.HTTPFlow) -> None:
    handlers.response(flow)


def load(loader):
    ctx.log.info("Registering option 'source_dir'")
    loader.add_option(
        "source_dir", str, "", (
            "An absolute path used as a source directory to"
            "lookup for mock rules"
        )
    )
    ctx.log.info("Registering option 'storage_dir'")
    loader.add_option(
        "storage_dir", str, "", (
            "Storage dir"
        )
    )
    return driver.register()


def configure(updated):
    reload = False
    if "source_dir" in updated:
        ctx.log.info("source_dir value: %s" % ctx.options.source_dir)
    if "storage_dir" in updated:
        ctx.log.info("source_dir value: %s" % ctx.options.storage_dir)
    if ctx.options.source_dir and ctx.options.storage_dir:
        driver.reload()
        ctx.log.info("driver reloaded...")
