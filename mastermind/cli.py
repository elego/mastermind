from __future__ import (absolute_import, print_function, division)
from itertools import repeat
import argparse
import os
import pytoml as toml
import sys

from . import version


def args():
    """
        Argument parser constructor.

        The main purpose is to allow tests to reuse the same CLI.
    """

    parser = argparse.ArgumentParser(
                prog="mastermind",
                description="Man in the middle testing tool")

    parser.add_argument("--version",
                        action="version",
                        version="%(prog)s" + " " + version.VERSION)

    parser.add_argument("--pid",
                        action="store_true",
                        help="Returns the PID for the given host and port")

    driver = parser.add_argument_group("Driver")
    single = parser.add_argument_group("Single")
    script = parser.add_argument_group("Script")

    driver.add_argument("--with-driver",
                        action="store_true",
                        help="Activates the driver")
    driver.add_argument("--source-dir",
                        metavar="DIR",
                        help="""An absolute path used as a source directory to
                                lookup for mock rules""")

    driver.add_argument("--config",
                        metavar="CONFIG_FILE",
                        help="""A valid config file. See
                                https://github.com/ustwo/mastermind""" +
                                "/tree/master/docs/config.md")

    single.add_argument("--response-body",
                        metavar="FILEPATH",
                        help="A file containing the mocked response body")
    single.add_argument("--url",
                        metavar="URL",
                        help="A URL to mock its response")

    script.add_argument("--script",
                        metavar="FILEPATH",
                        help='''A mitmproxy Python script filepath.
                                When passed, --response-body and
                                --url are ignored''')

    parser.add_argument("--listen-port",
                        help="Default port 8080")
    parser.add_argument("--listen-host",
                        help="Default host 0.0.0.0")
    parser.add_argument("--without-proxy-settings",
                        action="store_true",
                        help="Skips changing the OS proxy settings")

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("--quiet",
                                 action="store_true",
                                 help="Makes Mastermind quiet")

    verbosity_group.add_argument("-v", "--verbose",
                                 action="count",
                                 help="Makes Mastermind verbose")

    return parser


def mitm_args(config):
    """
        Creates valid mitmproxy arguments as expected by the main functions
        `mitmdump` and `mitmproxy` from the configuration dict.

        See `config` and `merge` for more details on the config data structure.
    """

    if "source-dir" in config["core"]:
        return driver_mode(config)
    elif "script" in config["core"]:
        return script_mode(config)
    elif ("response-body" in config["core"]) and ("url" in config["core"]):
        return simple_mode(config)
    else:
        return Exception("""The arguments used don't match any of the possible
                            modes. Check the help for more information.""")


def default_config():
    proxy_settings = sys.platform == "darwin"
    return {"core": {"verbose": 2,
                     "listen-host": "0.0.0.0",
                     "listen-port": 8080},
            "mitm": {},
            "os": {"proxy-settings": proxy_settings}}


def config(args):
    config = default_config()

    if args.config:
        with open(args.config) as config_file:
            data = toml.loads(config_file.read())
            if "os" in data:
                config["os"].update(data["os"])
            if "core" in data:
                config["core"].update(data["core"])

    if config["os"]["proxy-settings"] is True and (sys.platform != "darwin"):
        raise StandardError("Proxy settings is only available on Mac OX")

    return merge(config, args)


def base_path():
    return os.path.dirname(os.path.realpath(__file__))


def storage_path():
    path = os.getcwd().split("/")[-1]

    return os.path.expanduser("~/.mastermind/{}".format(path))


def merge(config, args):
    """
        Merges config coming from default_config and arguments passed via CLI.

        FIXME: Find a nicer way to merge args with config.
    """

    if args.listen_host:
        config["core"]["listen-host"] = args.client_host

    if args.listen_port:
        config["core"]["listen-port"] = args.client_port

    if args.verbose:
        config["core"]["verbose"] = args.verbose

    if args.quiet:
        config["core"]["verbose"] = 0

    if args.source_dir:
        config["core"]["source-dir"] = args.source_dir

    if args.script:
        config["core"]["script"] = args.script

    if args.response_body:
        config["core"]["response-body"] = args.response_body

    if args.url:
        config["core"]["url"] = args.url

    if args.without_proxy_settings:
        config["os"]["proxy-settings"] = False

    return config


def simple_mode(config):
    if not ("response-body" in config["core"] and "url" in config["core"]):
        return Exception("Simple mode requires response-body and url flags")

    script_path = os.path.dirname(os.path.realpath(__file__))

    if getattr(sys, 'frozen', False):
        script_path = sys._MEIPASS

    url = config["core"]["url"]
    response_body = config["core"]["response-body"]

    script_arg = ["--script", f"""{script_path}/scripts/flasked.py""",
                  "--set", f"""url={url}""",
                  "--set", f"""response_body={response_body}"""]

    return common_args(config) + script_arg + verbosity_args(config)


def script_mode(config):
    if bool([x for x
            in ["response-body", "url"]
            if x in config["core"].keys()]):

        return Exception("""The Script mode does not allow a
                            response body or a URL.""")

    script_arg = ["--script", config["core"]["script"]]

    return common_args(config) + script_arg + verbosity_args(config)


def driver_mode(config):
    if bool([x for x
            in ["script", "response-body", "url"]
            if x in config["core"].keys()]):

        return Exception("""The Driver mode does not allow a
                            script, a response body or a URL.""")

    config["core"]["storage-dir"] = storage_path()

    if not os.path.isdir(storage_path()):
        os.makedirs(storage_path())

    script_path = os.path.dirname(os.path.realpath(__file__))
    if getattr(sys, 'frozen', False):
        script_path = sys._MEIPASS

    source_dir = config["core"]["source-dir"]
    storage_dir = config["core"]["storage-dir"]
    listen_host = config["core"]["listen-host"]
    listen_port = config["core"]["listen-port"]

    script_arg = ["--script", f"""{script_path}/scripts/flasked.py""",
                  "--set", f"""source-dir={source_dir}""",
                  "--set", f"""storage-dir={storage_dir}""",
                  "--set", f"""listen-host={listen_host}""",
                  "--set", f"""listen-port={str(listen_port)}"""]

    return common_args(config) + script_arg + verbosity_args(config)


def common_args(config):
    return ["--showhost",
            "--listen-port", str(config["core"]["listen-port"]),
            "--listen-host", config["core"]["listen-host"]]


def verbosity_args(config):
    """
        Verbosity is splitted in (3, 3), the first set mastermind's verbosity,
        the second mitmproxy's.
    """

    verbose = config["core"]["verbose"]

    if verbose <= 3:
        return ["--quiet"]

    else:
        return list(repeat("-v", verbose - 3 if verbose <= 6 else 3))
