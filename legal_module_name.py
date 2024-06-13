import re


def is_legal_module_name(name):
    # Check length constraint
    if len(name) > 214:
        return False

    # Check if the name starts with a dot or an underscore
    if name.startswith('.') or name.startswith('_'):
        return False

    # Check if the name contains any spaces
    if ' ' in name:
        return False

    # Check if the name starts with "node_modules"
    if name.startswith('node_modules'):
        return False

    return True
