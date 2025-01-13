#!/usr/bin/env python3
"""
Validate if given list of files are encrypted with sops.
"""
from argparse import ArgumentParser
import json
from ruamel.yaml import YAML
from ruamel.yaml.parser import ParserError
from dotenv import dotenv_values
import sys
import re

yaml = YAML(typ='safe')

def validate_enc(key, item, encrypted_regex, is_encrypted=False):
    """
    Validate given item is concerned by the encrypted_regex and is correctly encrypted.

    All leaf values in a sops encrypted file must be strings that
    start with ENC[. We iterate through lists and dicts, checking
    only for leaf strings. Presence of any other data type (like
    bool, number, etc) also makes the file invalid except an empty
    string which would pass the encryption check.
    """

    # All childs should be encrypted
    if (encrypted_regex.search(key)):
        is_encrypted = True
    
    if isinstance(item, str):
        if not is_encrypted or (is_encrypted and (item == "" or item.startswith('ENC['))):
            return True
    elif isinstance(item, list):
        return all(validate_enc(key, value, encrypted_regex, is_encrypted) for key, value in item)
    elif isinstance(item, dict):
        return all(validate_enc(key, value, encrypted_regex, is_encrypted) for key, value in item.items())
    else:
        return False

# Search a value in a doc, valid for .env and .yaml/.json
def search_value(doc, path):
    keys = path.split(".")
    for key in keys:
        doc = doc.get(key, {})
    return doc if doc else None

def check_file(filename):
    """
    Check if a file has been encrypted properly with sops.

    Returns a boolean indicating wether given file is valid or not, as well as
    a string with a human readable success / failure message.
    """
    regex_search = 'sops.encrypted_regex'
    # sops doesn't have a --verify (https://github.com/mozilla/sops/issues/437)
    # so we implement some heuristics, primarily to guard against unencrypted
    # files being checked in.
    with open(filename) as f:
        try:
            # All YAML is valid JSON *except* if it contains hard tabs, and the default go
            # JSON outputter uses hard tabs, and since sops is written in go it does the same.
            # So we can't just use a YAML loader here - we use a yaml one if it ends in
            # .yaml, but json otherwise
            if filename.endswith('.yaml'):
                doc = yaml.load(f)
            elif filename.endswith('.env'):
                doc = dotenv_values(stream=f)
                regex_search = 'sops_encrypted_regex'
            else:
                doc = json.load(f)
        except ParserError:
            # All sops encrypted files are valid JSON, YAML or ENV
            return False, f"{filename}: Not valid JSON, YAML or ENV is not properly encrypted"

    # sops key is for JSON/YAML and sops_mac is for .env files
    if 'sops' not in doc and 'sops_mac' not in doc:
        # sops puts a `sops` key in the encrypted output. If it is not
        # present, very likely the file is not encrypted.
        return False, f"{filename}: sops metadata key not found in file, is not properly encrypted"

    invalid_keys = []

    # Searching the encrypted regex
    encrypted_regex = search_value(doc, regex_search)
    if encrypted_regex is None:
        return False, f"{filename}: the encrypted_regex hasn't been found"
        
    for k in doc:
        if k != 'sops' and not k.startswith('sops_'):
            # Values under the `sops` key are not encrypted.
            if not validate_enc(k, doc[k], re.compile(encrypted_regex)):
                # Collect all invalid keys so we can provide useful error message
                invalid_keys.append(k)

    if invalid_keys:
        return False, f"{filename}: Unencrypted values found nested under keys: {','.join(invalid_keys)}"

    return True, f"{filename}: Valid encryption"

def main():
    argparser = ArgumentParser()
    argparser.add_argument('filenames', nargs='+')

    args = argparser.parse_args()

    failed_messages = []

    for f in args.filenames:
        is_valid, message = check_file(f)

        if not is_valid:
            failed_messages.append(message)

    if failed_messages:
        print('\n'.join(failed_messages))
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
