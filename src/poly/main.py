import ast
import click
import hashlib
import json
import jwt
import os
import pyperclip
import re
import sys
import toml
import urllib.parse
import yaml

from base64 import b64decode, b64encode
from click import group, echo
from PIL import ImageColor
from random import randrange
from rich.console import Console
from rich.syntax import Syntax
from typing import Callable


def print_code(code: str, fmt: str) -> None:
    try:
        color = int(os.environ.get('POLY_CFG_COLOR', '1')) == 1
    except ValueError:
        color = True
    if not color:
        echo(code)
    else:
        syntax = Syntax(code, fmt, theme='monokai', line_numbers=True)
        c = Console()
        c.print(syntax)


# region error handling
def handle_unknown_error(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            echo('Unknown error occurred')
            echo(f'---------------\nClipboard:\n{pyperclip.paste()}')
            echo(f'---------------\n{str(e)}')
            sys.exit(1)

    return wrapper


# endregion


# region clipboard functions
def get_clipboard() -> str:
    data = pyperclip.paste()
    if not data:
        echo('No text in the clipboard')
        sys.exit(1)
    return data


@handle_unknown_error
def get_json_from_clipboard(verbose: bool = False) -> dict:
    try:
        return json.loads(get_clipboard())
    except json.JSONDecodeError as e:
        echo('No valid json in the clipboard')
        if verbose:
            echo(f'---------------\n{str(e)}')
        sys.exit(1)


@handle_unknown_error
def get_yaml_from_clipboard(verbose: bool = False) -> dict:
    try:
        return yaml.safe_load(get_clipboard())
    except yaml.YAMLError as e:
        echo('No valid yaml in the clipboard')
        if verbose:
            echo(f'---------------\n{str(e)}')
        sys.exit(1)


@handle_unknown_error
def get_toml_from_clipboard(verbose: bool = False) -> dict:
    try:
        return toml.loads(get_clipboard())
    except toml.decoder.TomlDecodeError as e:
        echo('No valid toml in the clipboard')
        if verbose:
            echo(f'---------------\n{str(e)}')
        sys.exit(1)


@handle_unknown_error
def get_jwt_from_clipboard(secret: str = '', algorithm: str = 'HS256') -> dict:
    algorithm = algorithm.upper()
    try:
        if not secret:
            return jwt.decode(get_clipboard(), options={'verify_signature': False}, algorithms=[algorithm])
        return jwt.decode(get_clipboard(), secret, algorithms=[algorithm])
    except jwt.exceptions.InvalidSignatureError:
        echo('Signature verification failed')
        sys.exit(1)
    except jwt.exceptions.InvalidAlgorithmError:
        echo('Invalid algorithm')
        sys.exit(1)


@handle_unknown_error
def get_query_params_from_clipboard(include_url: bool, unquote: bool, quote_plus: bool = False) -> dict:
    url = pyperclip.paste()
    parts = url.split('?')
    if len(parts) == 2:
        param_str = parts[1]
        if include_url:
            param_str += f'&url={parts[0]}'
    elif len(parts) == 1:
        param_str = parts[0]
    else:
        echo('No valid query string in clipboard')
        sys.exit(1)
    if unquote:
        param_str = urllib.parse.unquote_plus(param_str) if quote_plus else urllib.parse.unquote(param_str)
    params = urllib.parse.parse_qs(param_str)
    data = {}
    try:
        for k, v in params.items():
            data[k] = v[0] if len(v) == 1 else v
    except ValueError:
        echo('No valid query string in clipboard')
        sys.exit(1)
    return data


@handle_unknown_error
def get_hex_from_clipboard(rgba: bool = False) -> str:
    small, large = (4, 8) if rgba else (3, 6)
    reg = re.compile(f'#?(?:[A-F0-9]{{{small}}}|[A-F0-9]{{{large}}})')
    data = get_clipboard()
    if not reg.match(data.upper()):
        echo('No valid hex color string on the clipboard')
        sys.exit(1)
    return data


@handle_unknown_error
def get_rgb_from_clipboard() -> tuple[int, int, int]:
    data = get_clipboard()
    if not re.match(r'\(?\d{1,3}, ?\d{1,3}, ?\d{1,3}\)?', data):
        echo('No valid RGB color string on the clipboard, needs to be format (0, 0, 0)')
        sys.exit(1)
    return ast.literal_eval(data)


@handle_unknown_error
def get_rgba_from_clipboard() -> tuple[int, int, int, int]:
    data = get_clipboard()
    if not re.match(r'\(?\d{1,3}, ?\d{1,3}, ?\d{1,3}, ?\d{1,3}\)?', data):
        echo('No valid RGBA color string on the clipboard, needs to be format (0, 0, 0, 0)')
        sys.exit(1)
    return ast.literal_eval(data)


# endregion


# region converter functions
@handle_unknown_error
def to_json(data: dict, fancy=False):
    pyperclip.copy(json.dumps(data, indent=4) if fancy else json.dumps(data))
    print_code(pyperclip.paste(), 'json')


@handle_unknown_error
def to_yaml(data: dict):
    pyperclip.copy(yaml.dump(data, sort_keys=False))
    print_code(pyperclip.paste(), 'yaml')


@handle_unknown_error
def to_toml(data: dict):
    pyperclip.copy(toml.dumps(data))
    print_code(pyperclip.paste(), 'toml')


@handle_unknown_error
def to_jwt(data: dict, secret: str, algorithm: str, verbose: bool):
    algorithm = algorithm.upper()
    try:
        pyperclip.copy(jwt.encode(data, secret, algorithm=algorithm))
    except NotImplementedError:
        echo(f"Algorithm '{algorithm}' not supported")
        sys.exit(1)
    except ValueError as e:
        echo(f"Could not encode data with '{algorithm}'")
        if verbose:
            echo(f'---------------\n{str(e)}')
        sys.exit(1)
    echo(pyperclip.paste())


@handle_unknown_error
def to_b64(data: str):
    pyperclip.copy(b64encode(data.encode('utf-8')).decode('utf-8'))
    echo(pyperclip.paste())


@handle_unknown_error
def from_b64(data: str):
    pyperclip.copy(b64decode(data.encode('utf-8')).decode('utf-8'))
    echo(pyperclip.paste())


@handle_unknown_error
def to_hash(data: str, hashfn: Callable):
    pyperclip.copy(hashfn(data.encode('utf-8')).hexdigest())
    echo(pyperclip.paste())


@handle_unknown_error
def to_spongebob_case(data: str) -> str:
    return ''.join([c.upper() if randrange(0, 2) else c.lower() for c in data])


@handle_unknown_error
def convert_string_dict(data: dict) -> dict:
    def convert_value(v: str):
        if v.lower() in ['null', 'none']:
            v = 'None'
        elif v.lower() in ['true', 'false']:
            v = str(f'{v[0].upper()}{v[1:].lower()}')
        try:
            v = ast.literal_eval(v)
        except (ValueError, SyntaxError):
            v = v
        return v

    return {
        k: [convert_value(val) for val in value] if isinstance(value, list) else convert_value(value)
        for k, value in data.items()
    }


@handle_unknown_error
def to_query_string(data: dict, quote: bool, quote_plus: bool = False):
    def fix_value(val):
        if not isinstance(val, str):
            val = json.dumps(val)
        if quote:
            return urllib.parse.quote_plus(val) if quote_plus else urllib.parse.quote(val)
        return val

    q_str = ''
    for key, value in data.items():
        if isinstance(value, list):
            for v in value:
                q_str += f'&{key}={fix_value(v)}'
        else:
            q_str += f'&{key}={fix_value(value)}'
    q_str = q_str[1:]
    pyperclip.copy(q_str)
    echo(pyperclip.paste())


@handle_unknown_error
def slack_to_chat(data: str, strip_time: bool, strip_img: bool) -> str:
    # Pulls emoji reactions off the chat
    emoji_regex = re.compile(r':.+:')
    # Pulls thread information off the chat
    thread_start_regex = re.compile(r'^\d+ repl(?:y|ies)$')
    thread_regex = re.compile(r'^(?:[\w ]+)?\d+ \w+ agoView thread$')
    # Identifies when a line is a user's name/datetime
    sender_regex = re.compile(r'^(?P<name>.+) {2}(?P<time>\d+:\d+)$')
    # Strips out emoji statuses on sender names
    sender_no_emoji_regex = re.compile(r'^(?P<name>\w+)(?::[\w\-]+:)?$')
    # Identifies the timestamp for "secondary lines" after the first message for a user
    secondary_regex = re.compile(r'^(?P<time>\d+:\d+)$')
    # Identifies when you copied an image/video, and it shows a title
    # Probably missing some extensions but this should cover like 99% of them
    attach_regex = re.compile(r'^[\w_\-]*\.(png|jpe?g|gif|tiff|mov|mp4|m4v|webm|mkv|mpe?g4?|avi|vid) ?$')
    lines = [x for x in data.split('\n') if x != '']
    final = []
    # If they copy starting at a "secondary line" we won't know who sent the first message
    sender = 'Unknown'
    # Tracking for the times on the next "secondary line"
    time = ''
    # Tracking for finding a secondary line
    found_next = False
    # Tracking for when you're finding emoji reactions.  So many reactions...
    found_emoji = False
    # Tracking for finding "thread" details
    found_thread = False
    for line in lines:
        # If they want, we skip those image/video titles
        if strip_img and attach_regex.match(line):
            continue
        # Drop that emoji crap
        if emoji_regex.match(line):
            found_emoji = True
            continue
        # That thread crap too
        if found_thread and thread_regex.match(line):
            found_thread = False
            continue
        if thread_start_regex.match(line):
            found_thread = True
            continue
        # This is for the "emoji count" for each reaction.
        # Shows up as its own line cuz why not?
        if found_emoji and re.match(r'\d+', line):
            found_emoji = False
            continue
        found_emoji = False
        # Primary sender line match
        sender_match = sender_regex.match(line)
        if sender_match:
            parts = sender_match.groupdict()
            sner_match = sender_no_emoji_regex.match(parts['name'])
            sender = sner_match.groupdict()['name']
            time = parts['time']
            continue
        # "Secondary line" match
        sec_match = secondary_regex.match(line)
        if sec_match and not found_next:  # Accounts for people sending the time as a message
            time = sec_match.groupdict()['time']
            found_next = True
            continue
        found_next = False
        # If we get here, it's a normal line of text hopefully...
        time_fmt = '' if strip_time else f' ({time})'
        final.append(f'{sender}{time_fmt}:  {line}')
    return '\n'.join(final)


# endregion


@group()
def poly():
    pass


# region json commands
@poly.group(name='json', help='Convert JSON data to various formats')
def json_group():
    pass


@json_group.command(name='pretty', help='Pretty-print JSON data')
@click.option('-v', '--verbose', is_flag=True)
def pretty(verbose: bool):
    data = get_json_from_clipboard(verbose)
    to_json(data, fancy=True)


@json_group.command(name='one-line', help='Compress JSON to a single line string')
@click.option('-v', '--verbose', is_flag=True)
def one_line(verbose: bool):
    data = get_json_from_clipboard(verbose)
    to_json(data)


@json_group.command(name='yaml', help='Convert JSON -> YAML')
@click.option('-v', '--verbose', is_flag=True)
def json_yaml(verbose: bool):
    data = get_json_from_clipboard(verbose)
    to_yaml(data)


@json_group.command(name='toml', help='Convert JSON -> TOML')
@click.option('-v', '--verbose', is_flag=True)
def json_toml(verbose: bool):
    data = get_json_from_clipboard(verbose)
    to_toml(data)


@json_group.command(name='jwt', help='Convert JSON -> JWT')
@click.option('-s', '--secret', required=True, help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=True, help='The algorithm to use for decoding')
@click.option('-v', '--verbose', is_flag=True)
def json_jwt(secret: str, algorithm: str, verbose: bool):
    data = get_json_from_clipboard(verbose)
    to_jwt(data, secret, algorithm, verbose)


@json_group.command(name='query-string', help='Convert JSON -> Query Params')
@click.option('-v', '--verbose', is_flag=True)
def json_query_string(verbose: bool):
    data = get_json_from_clipboard(verbose)
    to_query_string(data, quote=False)


# endregion


# region yaml commands
@poly.group(name='yaml', help='Convert YAML data to various formats')
def yaml_group():
    pass


@yaml_group.command(name='json', help='Convert YAML -> JSON')
@click.option('-v', '--verbose', is_flag=True)
def yaml_json(verbose: bool):
    data = get_yaml_from_clipboard(verbose)
    to_json(data)


@yaml_group.command(name='toml', help='Convert YAML -> TOML')
@click.option('-v', '--verbose', is_flag=True)
def yaml_toml(verbose: bool):
    data = get_yaml_from_clipboard(verbose)
    to_toml(data)


@yaml_group.command(name='jwt', help='Convert YAML -> JWT')
@click.option('-s', '--secret', required=True, help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=True, help='The algorithm to use for decoding')
@click.option('-v', '--verbose', is_flag=True)
def yaml_jwt(secret: str, algorithm: str, verbose: bool):
    data = get_yaml_from_clipboard(verbose)
    to_jwt(data, secret, algorithm, verbose)


@yaml_group.command(name='query-string', help='Convert YAML -> Query params')
@click.option('-v', '--verbose', is_flag=True)
def yaml_query_string(verbose: bool):
    data = get_yaml_from_clipboard(verbose)
    to_query_string(data, quote=False)


# endregion


# region toml commands
@poly.group(name='toml', help='Convert TOML data to various formats')
def toml_group():
    pass


@toml_group.command(name='yaml', help='Convert TOML -> YAML')
@click.option('-v', '--verbose', is_flag=True)
def toml_yaml(verbose: bool):
    data = get_toml_from_clipboard(verbose)
    to_yaml(data)


@toml_group.command(name='json', help='Convert TOML -> JSON')
@click.option('-v', '--verbose', is_flag=True)
def toml_json(verbose: bool):
    data = get_toml_from_clipboard(verbose)
    to_json(data)


@toml_group.command(name='jwt', help='Convert TOML -> JWT')
@click.option('-s', '--secret', required=True, help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=True, help='The algorithm to use for decoding')
@click.option('-v', '--verbose', is_flag=True)
def toml_jwt(secret: str, algorithm: str, verbose: bool):
    data = get_toml_from_clipboard(verbose)
    echo(data)
    to_jwt(data, secret, algorithm, verbose)


@toml_group.command(name='query-string', help='Convert TOML -> Query params')
@click.option('-v', '--verbose', is_flag=True)
def toml_query_string(verbose: bool):
    data = get_toml_from_clipboard(verbose)
    to_query_string(data, quote=False)


# endregion


# region jwt commands
@poly.group(name='jwt', help='Convert a JWT to various formats')
def jwt_group():
    pass


@jwt_group.command(name='json', help='Convert JWT -> JSON')
@click.option('-s', '--secret', required=False, default='', help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=False, default='HS256', help='The algorithm to use for decoding')
@click.option('-p', '--pretty', is_flag=True, help='Format the JSON output')
def jwt_json(secret: str, algorithm: str, pretty: bool):
    data = get_jwt_from_clipboard(secret, algorithm)
    to_json(data, pretty)


@jwt_group.command(name='yaml', help='Convert JWT -> YAML')
@click.option('-s', '--secret', required=True, help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=True, help='The algorithm to use for decoding')
def jwt_yaml(secret: str, algorithm: str):
    data = get_jwt_from_clipboard(secret, algorithm)
    to_yaml(data)


@jwt_group.command(name='toml', help='Convert JWT -> TOML')
@click.option('-s', '--secret', required=True, help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=True, help='The algorithm to use for decoding')
def jwt_toml(secret: str, algorithm: str):
    data = get_jwt_from_clipboard(secret, algorithm)
    to_toml(data)


@jwt_group.command(name='query-string', help='Convert JWT -> Query params')
@click.option('-s', '--secret', required=True, help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=True, help='The algorithm to use for decoding')
def jwt_query_string(secret: str, algorithm: str):
    data = get_jwt_from_clipboard(secret, algorithm)
    to_query_string(data, quote=False)


# endregion


# region query string commands
@poly.group(name='query-string', help='Convert a query param string to various formats')
def query_string():
    pass


@query_string.command(name='json', help='Convert Query params -> JSON')
@click.option('-p', '--pretty', is_flag=True, help='If present, the JSON output will be prettified')
@click.option(
    '-c', '--convert', is_flag=True, help='If present, poly will attempt to convert the strings to valid types for JSON'
)
@click.option('-u', '--include-url', is_flag=True, help="If present, the URL will also be included with the 'url' key")
def query_string_json(pretty: bool, convert: bool, include_url: bool):
    data = get_query_params_from_clipboard(include_url, unquote=False)
    if convert:
        data = convert_string_dict(data)
    to_json(data, pretty)


@query_string.command(name='yaml', help='Convert Query params -> YAML')
@click.option(
    '-c', '--convert', is_flag=True, help='If present, poly will attempt to convert the strings to valid types for YAML'
)
@click.option('-u', '--include-url', is_flag=True, help="If present, the URL will also be included with the 'url' key")
def query_string_yaml(convert: bool, include_url: bool):
    data = get_query_params_from_clipboard(include_url, unquote=False)
    if convert:
        data = convert_string_dict(data)
    to_yaml(data)


@query_string.command(name='toml', help='Convert Query params -> TOML')
@click.option(
    '-c', '--convert', is_flag=True, help='If present, poly will attempt to convert the strings to valid types for TOML'
)
@click.option('-u', '--include-url', is_flag=True, help="If present, the URL will also be included with the 'url' key")
def query_string_toml(convert: bool, include_url: bool):
    data = get_query_params_from_clipboard(include_url, unquote=False)
    if convert:
        data = convert_string_dict(data)
    to_toml(data)


@query_string.command(name='jwt', help='Convert Query params -> JWT')
@click.option('-s', '--secret', required=True, help='The secret to use for decoding')
@click.option('-a', '--algorithm', required=True, help='The algorithm to use for decoding')
@click.option(
    '-c', '--convert', is_flag=True, help='If present, poly will attempt to convert the strings to valid types for JSON'
)
@click.option('-u', '--include-url', is_flag=True, help="If present, the URL will also be included with the 'url' key")
@click.option('-v', '--verbose', is_flag=True)
def query_string_jwt(secret: str, algorithm: str, convert: bool, include_url: bool, verbose: bool):
    data = get_query_params_from_clipboard(include_url, unquote=False)
    if convert:
        data = convert_string_dict(data)
    to_jwt(data, secret, algorithm, verbose)


# endregion


# region url commands
@poly.group(name='url', help='Manipulate strings using URL Encoding')
def poly_url():
    pass


@poly_url.command(name='encode', help='Encode a string with URL-encoding')
@click.option('-q', '--quote-plus', is_flag=True, help="If present, will encode spaces as '+' rather than '%20'")
def encode(quote_plus: bool):
    data = get_query_params_from_clipboard(False, unquote=False)
    to_query_string(data, quote=True, quote_plus=quote_plus)


@poly_url.command(name='decode', help='Decode a URL-encoded string')
@click.option('-q', '--quote-plus', is_flag=True, help="If present, this will decode the query string '+' as a space")
def decode(quote_plus: bool):
    data = get_query_params_from_clipboard(False, unquote=True, quote_plus=quote_plus)
    to_query_string(data, quote=False, quote_plus=quote_plus)


# endregion


# region base64 commands
@poly.group(name='b64', help='Manipulate strings with base-64 encoding')
def b64_group():
    pass


@b64_group.command(name='from', help='Decode a base-64 encoded string')
def from_cmd():
    data = get_clipboard()
    from_b64(data)


@b64_group.command(name='to', help='Encode a string as base-64')
def to():
    data = get_clipboard()
    to_b64(data)


# endregion


# region hashfunc commands
@poly.command(name='md5', help='MD5 hash conversion')
def md5_hash():
    data = get_clipboard()
    to_hash(data, 'MD5', hashlib.md5)


@poly.command(name='sha1', help='SHA1 hash conversion')
def sha1_hash():
    data = get_clipboard()
    to_hash(data, 'SHA1', hashlib.sha1)


@poly.command(name='sha256', help='SHA256 hash conversion')
def sha256_hash():
    data = get_clipboard()
    to_hash(data, 'SHA256', hashlib.sha256)


@poly.command(name='sha512', help='SHA512 hash conversion')
def sha512_hash():
    data = get_clipboard()
    to_hash(data, 'SHA512', hashlib.sha512)


# endregion


# region color conversion commands
# region hex conversion
@poly.group(name='hex', help='Convert Hex colors to other formats')
def hex_group():
    pass


@hex_group.command(name='rgb', help='Convert Hex -> RGB')
def hex_rgb():
    data = get_hex_from_clipboard()
    color = ImageColor.getcolor(data, 'RGB')
    pyperclip.copy(str(color))
    echo(pyperclip.paste())


@hex_group.command(name='rgba', help='Convert Hex -> RGBA')
def hex_rgba():
    data = get_hex_from_clipboard()
    color = ImageColor.getcolor(data, 'RGBA')
    pyperclip.copy(str(color))
    echo(pyperclip.paste())


# endregion


# region rgb conversion
@poly.group(name='rgb', help='Convert RGB colors to other formats')
def rgb_group():
    pass


@rgb_group.command(name='hex', help='Convert RGB -> Hex')
def rgb_hex():
    r, g, b = get_rgb_from_clipboard()
    pyperclip.copy(f'#{r:02x}{g:02x}{b:02x}'.upper())
    echo(pyperclip.paste())


# endregion


# region rgba conversion
@poly.group(name='rgba', help='Convert RGBA colors to other formats')
def rgba_group():
    pass


@rgba_group.command(name='hex', help='Convert RGBA -> Hex')
def rgba_hex():
    r, g, b, a = get_rgba_from_clipboard()
    pyperclip.copy(f'#{r:02x}{g:02x}{b:02x}{a:02x}'.upper())
    echo(pyperclip.paste())


# endregion
# endregion


# region string manipulation commands
@poly.command(name='quotes', help='Fixes smart quotes [“”‘’] into normal quotes ["\']')
def quotes():
    unfixed = pyperclip.paste()
    tmp = re.sub(r'[“”]', '"', unfixed)
    fixed = re.sub(r'[‘’]', "'", tmp)
    pyperclip.copy(fixed)
    echo(pyperclip.paste())


@poly.command(name='spongebob', help='I wondEr wHat ThIs does')
def spongebob():
    unfixed = pyperclip.paste()
    fixed = to_spongebob_case(unfixed)
    pyperclip.copy(fixed)
    echo(pyperclip.paste())


@poly.command(name='sort-lines', help='Sort newline-separated lines')
@click.option('-r', '--reverse', is_flag=True, help='If present, sorting is reversed')
@click.option('-s', '--strip-empty', is_flag=True, help='If present, empty lines will be stripped from the output')
def sort_lines(reverse: bool, strip_empty: bool):
    lines = pyperclip.paste().split('\n')
    sorted_lines = sorted(lines, reverse=reverse)
    if strip_empty:
        sorted_lines = [s for s in sorted_lines if s != '']
    pyperclip.copy('\n'.join(sorted_lines))
    echo(pyperclip.paste())


@poly.command(name='escape', help="Add escape character '\\' before character(s)")
@click.argument('characters')
def escape(characters: str):
    data = get_clipboard()
    if '\\' in characters:
        data = data.replace('\\', '\\\\')
    characters = characters.replace('\\', '')
    for char in characters:
        data = data.replace(char, f'\\{char}')
    pyperclip.copy(data)
    echo(pyperclip.paste())


@poly.command(name='unescape', help="Remove escape character '\\' from before character(s)")
@click.argument('characters')
def unescape(characters: str):
    data = get_clipboard()
    for char in characters:
        data = data.replace(f'\\{char}', char)
    pyperclip.copy(data)
    echo(pyperclip.paste())


# endregion


# region chat programs
@poly.command(name='slack', help='Strip out all the crap when copying from Slack')
@click.option('-t', '--strip-time', is_flag=True, help='Remove the timestamps to simplify output')
@click.option('-i', '--strip-img', is_flag=True, help='Remove the image labels to simplify output')
def slack(strip_time: bool, strip_img: bool):
    data = get_clipboard()
    final = slack_to_chat(data, strip_time, strip_img)
    pyperclip.copy(final)
    echo(pyperclip.paste())


# endregion


if __name__ == '__main__':
    poly()
