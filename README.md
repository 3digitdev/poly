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

**NOTE:  Some data types (like `null` in TOML) won't convert and might be dropped!**

### JWT Conversion

JWT requires two additional options:

- `-s, --secret`: A secret string to encode/decode with
- `-a, --algorithm`: An algorithm to encode/decode with

## JSON formatting (`json`)

Manipulate JSON data from the clipboard

All commands start with `poly json`

- `pretty`: pretty-prints the JSON in your clipboard and sends it back to the clipboard
- `one-line`: outputs the JSON in your clipboard as a single line of text and sends it back to the clipboard

## Base64 (`b64`)

Encode/Decode Base64 data

- `poly b64 from`: Takes base64-encoded data from the clipboard, outputs the decoded data, and sends it back to the clipboard
- `poly b64 to`: Takes data from the clipboard, outputs base64-encoded data, and sends it back to the clipboard
