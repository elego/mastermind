import pytest
import sys

import mastermind.cli as cli


def test_valid_simple_mode():
    base_path = cli.base_path()
    args = cli.args().parse_args(['--url', 'http://localhost',
                                  '--response-body', './foo.json'])
    config = cli.config(args)
    expected = ["--showhost",
                "--listen-port", "8080",
                "--listen-host", "0.0.0.0",
                "--script",
                "{}/scripts/simple.py".format(base_path),
                "http://localhost",
                "./foo.json",
                "--quiet"]

    assert cli.simple_mode(config) == expected


def test_no_url_simple_mode():
    args = cli.args().parse_args(['--response-body', './foo.json'])
    config = cli.config(args)

    assert type(cli.simple_mode(config)) == Exception


def test_no_response_body_simple_mode():
    args = cli.args().parse_args(['--url', 'http://localhost'])
    config = cli.config(args)

    assert type(cli.simple_mode(config)) == Exception


def test_valid_script_mode():
    args = cli.args().parse_args(['--script', '/foo.py bar'])
    config = cli.config(args)

    assert cli.script_mode(config) == ["--showhost",
                                       "--listen-port", "8080",
                                       "--listen-host", "0.0.0.0",
                                       "--script", "/foo.py bar",
                                       "--quiet"]


def test_unexpected_flags_script_mode():
    args = cli.args().parse_args(['--url', 'http://localhost'])
    config = cli.config(args)

    assert type(cli.script_mode(config)) == Exception


def test_valid_driver_mode():
    base_path = cli.base_path()
    storage_path = cli.storage_path()
    args = cli.args().parse_args(['--source-dir', '/foo/bar'])
    config = cli.config(args)
    expected = ["--showhost",
                "--listen-port", "8080",
                "--listen-host", "0.0.0.0",
                "--script",
                "{}/scripts/flasked.py".format(base_path),
                "/foo/bar",
                storage_path,
                "0.0.0.0",
                "8080",
                "--quiet"]

    assert cli.driver_mode(config) == expected


def test_unexpected_flags_driver_mode():
    args = cli.args().parse_args(['--url', 'http://localhost'])
    config = cli.config(args)

    assert type(cli.driver_mode(config)) == Exception


def test_verbosity_quiet():
    args = cli.args().parse_args(['--quiet'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["--quiet"]


def test_verbosity_1():
    args = cli.args().parse_args(['-v'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["--quiet"]


def test_verbosity_2():
    args = cli.args().parse_args(['-vv'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["--quiet"]


def test_verbosity_3():
    args = cli.args().parse_args(['-vvv'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["--quiet"]


def test_verbosity_4():
    args = cli.args().parse_args(['-vvvv'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["-v"]


def test_verbosity_5():
    args = cli.args().parse_args(['-vvvvv'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["-v", "-v"]


def test_verbosity_6():
    args = cli.args().parse_args(['-vvvvvv'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["-v", "-v", "-v"]


def test_verbosity_out_of_bounds():
    args = cli.args().parse_args(['-vvvvvvv'])
    config = cli.config(args)

    assert cli.verbosity_args(config) == ["-v", "-v", "-v"]


def test_valid_driver_mode_config_file():
    base_path = cli.base_path()
    storage_path = cli.storage_path()
    args = cli.args().parse_args(['--config', 'test/fixtures/simple.toml'])
    config = cli.config(args)
    expected = [
        "--showhost",
        "--listen-port", "8080",
        "--listen-host", "0.0.0.0",
        "--script",
        "{}/scripts/flasked.py".format(base_path),
        "./test/records",
        storage_path,
        "0.0.0.0",
        "8080",
        "--quiet"
    ]

    assert cli.driver_mode(config) == expected


def test_valid_config_file_with_overwrites():
    args = cli.args().parse_args(['--config', 'test/fixtures/simple.toml',
                                  '--source-dir', 'foo/bar',
                                  '-vvv',
                                  '--without-proxy-settings'])
    expected = {
        "core": {"listen-host": "0.0.0.0",
                 "listen-port": 8080,
                 "source-dir": "foo/bar",
                 "verbose": 3},
        "mitm": {},
        "os": {"proxy-settings": False}
    }

    assert cli.config(args) == expected


def test_valid_missing_config_file():
    args = cli.args().parse_args(['--config', 'fixtures/simple.toml'])
    with pytest.raises(IOError):
        cli.config(args)


if sys.platform != "darwin":
    def test_proxy_settings_not_osx():
        args = cli.args().parse_args(['--config',
                                      'test/fixtures/proxy-on.toml'])
        with pytest.raises(Exception):
            cli.config(args)


def test_config_file_defaults():
    args = cli.args().parse_args(['--config', 'test/fixtures/simple.toml'])
    expected = {
        "core": {"listen-host": "0.0.0.0",
                 "listen-port": 8080,
                 "source-dir": "./test/records",
                 "verbose": 2},
        "mitm": {},
        "os": {"proxy-settings": (sys.platform == "darwin")}
    }

    assert cli.config(args) == expected
