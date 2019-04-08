from __future__ import (absolute_import, print_function, division)
from urllib.parse import urlsplit, parse_qsl

from . import rfc6570


def is_template(url):
    """
        If a URL has variables it is assumed to be a URI Template (RFC 6570)
    """
    return len(rfc6570.varlist(url)) > 0


def eq(a, b):
    """
        Checks for equality based on different URI components and expands
        templates if any.
    """
    a_is_tpl = is_template(a)
    b_is_tpl = is_template(b)

    if a_is_tpl and b_is_tpl:
        False

    if a_is_tpl:
        a = expand_template(a, b)

    if b_is_tpl:
        b = expand_template(b, a)

    actual = parse(a)
    expected = parse(b)

    return (match_host(actual, expected) and
            match_schema(actual, expected) and
            match_path(actual, expected) and
            match_querystring(actual, expected))


def expand_template(template, reference):
    """
        Receives a template and a URI reference. Decomposes the reference into
        pairs and segments and returns a valid URI result of expanding the
        template.

        TODO: fragments (#) are ignored.
    """

    reference_split = parse(reference)
    segments = path_segments(reference_split.path)
    pairs = query_pairs(reference_split.query)

    return rfc6570.expand(template, pairs, segments)


def parse(uri):
    return urlsplit(uri)


def path_segments(path):
    """
        Receives a URI path (str) and returns its segments.
    """
    return list(filter(lambda x: len(x) > 0, path.split("/")))


def query_pairs(query):
    """
        Receives a URI querystring (str) and returns its pairs as tuples.
    """
    return parse_qsl(query, keep_blank_values=True)


def match_host(actual, expected):
    return expected.hostname == actual.hostname


def match_path(actual, expected):
    return expected.path == actual.path


def match_querystring(actual, expected):
    return sorted(parse_qsl(expected.query)) == sorted(parse_qsl(actual.query))


def match_schema(actual, expected):
    return expected.scheme == actual.scheme
