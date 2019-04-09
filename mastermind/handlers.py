
from __future__ import (absolute_import, print_function, division)
import time
import yaml
import mitmproxy
from mitmproxy import ctx
from mitmproxy.net.http import Headers

from . import (http, rules, validator)
from .driver import driver
from .say import logger


def request(flow: mitmproxy.http.HTTPFlow) -> None:
    flow.mastermind = {"rule": None}

    logger.info(flow.request.url)

    if driver.name:
        ruleset = rules.load(driver.name,
                             ctx.options.source_dir)
        filtered_rules = rules.select(flow.request.method,
                                      flow.request.url,
                                      ruleset)
        rule = rules.head(filtered_rules)

        if len(filtered_rules) > 1:
            mitmproxy.log("Too many rules: {}".format(
                map(rules.url, filtered_rules)))

        if rule:
            flow.mastermind['rule'] = rule
            mitmproxy.log("Intercepted URL: {}".format(rules.url(rule)))

            if rules.skip(rule):
                return flow.reply(http.response(204, headers=Headers()))

            rules.process_headers('request',
                                  rule,
                                  flow.request.headers)


def response(flow: mitmproxy.http.HTTPFlow) -> None:
    if driver.name:
        rule = flow.mastermind['rule']
        if rule:
            delay = rules.delay(rule)
            if delay:
                time.sleep(delay)

            status_code = rules.status_code(rule)
            body_filename = rules.body_filename(rule)
            schema = rules.schema(rule, ctx.options.source_dir)

            if status_code:
                status_message = http.status_message(status_code)

                flow.response.status_code = status_code
                flow.response.msg = status_message

            if schema:
                table = driver.db.table(flow.request.url)
                res = yaml.safe_load(flow.response.content)
                schema_result = validator.check(res, schema)
                table.insert_multiple(schema_result)
                logger.info(schema_result)

            rules.process_headers('response',
                                  rule,
                                  flow.response.headers)

            if body_filename:
                # 204 might be set by the skip rule in the request hook
                if flow.response.status_code == 204:
                    flow.response.status_code = 200
                    flow.response.msg = 'OK'
                flow.response.content = rules.body(body_filename,
                                                   ctx.options.source_dir)
