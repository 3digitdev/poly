# Poly

A simple command for converting and processing data from your clipboard.

## Installation

Copy the `poly` file to `/usr/bin` and make it executable

```sh
sudo chmod +x poly && cp poly /usr/bin/poly
```

Install the requirements

```sh
pip install -r requirements.txt
```

## Usage

You can generally convert data with the following format:

`poly <from_format> <to_format>[ options]`

You can manipulate data with the following format:

`poly <data_format> <command>[ options]`

You can find some basic help from the `--help` option at any level:

```sh
poly --help
poly json --help
poly yaml --help
```

## Conversions

All of the following formats convert between each other:

- JSON
- YAML
- TOML
- JWT
- URL Query String

**NOTE:  Some data types (like `null` in TOML) won't convert and might be dropped!**

### JWT Conversion

Converting to JWT requires two additional options:

- `-s, --secret`: A secret string to encode/decode with
- `-a, --algorithm`: An algorithm to encode/decode with

### Query String Type Conversion

When converting from a query string you can use the `-c, --convert` flag to tell `poly` to attempt to convert
all the values in the query string.  They all start as strings, but it will attempt to do things like convert `"true"` to `true` for JSON/YAML, etc.
This only works for the basic data types; it will not do anything smart like nested objects/lists.

_Example:_

assuming your clipboard contains `http://foo.bar.com?a=1&b=true&c=a,b,c`...

```sh
poly query-string json --convert
```

will result in
```json5
{
  "a": 1,
  "b": true,
  "c": "a,b,c"   // note that this is NOT ["a", "b", "c"]
}
```
`?foo=bar,baz,bat` will be converted as a string of `{"foo": "bar,baz,bat"}`, not as a list of `{"foo": ["bar", "baz", "bat"]}`_

This is done using the Python builtin `ast.literal_eval()` -- a completely save eval that will attempt simply to convert the string to a valid Python literal, and does not execute the code.

## JSON formatting (`json`)

Manipulate JSON data from the clipboard

All commands start with `poly json`

- `pretty`: pretty-prints the JSON in your clipboard and sends it back to the clipboard
- `one-line`: outputs the JSON in your clipboard as a single line of text and sends it back to the clipboard

## Base64 (`b64`)

Encode/Decode Base64 data

- `poly b64 from`: Takes base64-encoded data from the clipboard, outputs the decoded data, and sends it back to the clipboard
- `poly b64 to`: Takes data from the clipboard, outputs base64-encoded data, and sends it back to the clipboard

## Hash Functions

Supports `md5`, `sha1`, `sha256`, and `sha512`

## URL Query Param Encoding/Decoding

- `poly url encode`
- `poly url decode`

Encodes strings like

```
a=1&b=true&c=a,b,c&b=false&d={"foo": "bar", "baz": "bat"}
```

into

```
a=1&b=true&b=false&c=a%2Cb%2Cc&d=%7B%22foo%22%3A%20%22bar%22%2C%20%22baz%22%3A%20%22bat%22%7D
```

and decodes them back again.

Both `encode`/`decode` also support `-q, --quote-plus` which allows for encoding spaces as `+` instead of `%20`

## String Manipulation

- **Line sorting (`line-sort`)**: This will attempt to sort the lines of a `\n`-separated string in your clipboard
- **Spongebob (`sponge`, `spongebob`)**: _I WoNDeR What ThIS doEs_
- **Smart Quotes (`quotes`)**:  Replaces those stupid `“`/`”`/`‘`/`’` with proper quotes `"`/`'`
- **[Un]Escape Text (`escape`/`unescape`)**:  Add/remove `\` in a string for given characters
