from tree_sitter import Language, Parser
import jsbeautifier
import re
import math
from collections import Counter
import numpy as np
import tree_sitter_javascript as ts_javascript

JS_LANGUAGE = Language(ts_javascript.language())

# Create a new parser instance for JavaScript.
parser = Parser()
parser.set_language(JS_LANGUAGE)


def post_order_traversal(node):
    """
    Perform a post-order traversal of the syntax tree and return a list of node types.

    Parameters:
    - node: The current node in the syntax tree.

    Returns:
    - node_types: A list of node types in post-order traversal.
    """
    node_types = []
    for child in node.named_children:
        node_types.extend(post_order_traversal(child))
    node_types.append(node.type)
    return node_types


def pre_order_traversal(node):
    node_types = []
    node_types.append(node.type)
    for child in node.named_children:
        node_types.extend(pre_order_traversal(child))

    return node_types


def get_syntactic_units(js_file_path):
    with open(js_file_path, 'r') as file:
        code = file.read()
    tree = parser.parse(bytes(code, "utf8"))
    root_node = tree.root_node
    node_types = pre_order_traversal(root_node)
    return node_types


def cal_compression_ratio(code, lines_of_code):
    # call the compress ratio
    formatted_code = jsbeautifier.beautify(code)
    tree_formatted = parser.parse(bytes(formatted_code, "utf8"))
    lines_of_formatted_code = tree_formatted.root_node.end_point[0] + 1
    line_compression_ratio = 0
    if lines_of_formatted_code != 0 and isinstance(lines_of_formatted_code, (int, float)):
        line_compression_ratio = lines_of_code / lines_of_formatted_code

    spaces_in_code = len(re.findall(r' ', code))
    spaces_in_formatted_code = len(re.findall(r' ', formatted_code))
    space_compression_ratio = 0.0
    if spaces_in_formatted_code != 0:
        space_compression_ratio = spaces_in_code / spaces_in_formatted_code

    return [line_compression_ratio, space_compression_ratio]


def is_confusing_identifier(identifier):
    if len(identifier) < 2:
        return False
        # Define a simple heuristic rule: If an identifier contains only consonant letters,
        # it is considered to be a messy identifier
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{4,}', identifier.lower()):
        return True
    return False


def extract_all_identifier_features(root_node):
    # extract all identifiers
    query_id = JS_LANGUAGE.query("(identifier)@id")
    captures_id = query_id.captures(root_node)
    identifiers = [capture[0].text.decode('utf-8') for capture in captures_id]

    # extract all property identifiers
    query_property_id = JS_LANGUAGE.query("(property_identifier)@id")
    captures_property_id = query_property_id.captures(root_node)
    property_identifiers = [capture[0].text.decode('utf-8') for capture in captures_property_id]

    all_identifiers = identifiers + property_identifiers

    if len(all_identifiers) == 0:
        return [0, 0.0, 0]

    # confusing_id_count = sum(1 for id in all_identifiers if is_confusing_identifier(id))
    confusing_id_count = 0
    hex_numbers = 0
    unicode_numbers = 0
    octal_numbers = 0
    for identifier in all_identifiers:
        if is_confusing_identifier(identifier):
            confusing_id_count += 1
        hex_numbers += len(re.findall(r'0x[0-9A-Fa-f]+', identifier))
        unicode_numbers += len(re.findall(r'\\u[0-9A-Fa-f]{4}', identifier))
        octal_numbers += len(re.findall(r'0[0-7]+', identifier))
    special_numbers_count = hex_numbers + unicode_numbers + octal_numbers
    confusing_id_count += special_numbers_count

    # entropy
    sum_of_entropy = 0.0
    for id in all_identifiers:
        total_chars = len(id)
        frequencies = Counter(id)
        id_entropy = 0.0
        for char, freq in frequencies.items():
            probability = freq / total_chars
            id_entropy -= probability * math.log2(probability)
        sum_of_entropy += id_entropy
    entropy = sum_of_entropy / len(all_identifiers)
    if not isinstance(entropy, (int, float)):
        entropy = 0.0

    # prototype
    prototype_numbers = 0
    for property_identifier in property_identifiers:
        if property_identifier == 'prototype':
            prototype_numbers += 1

    return [confusing_id_count, entropy, prototype_numbers]


def extract_string_features(root_node):
    query_str = JS_LANGUAGE.query("(string_fragment)@str")
    captures_str = query_str.captures(root_node)
    strs = [capture[0].text.decode('utf-8') for capture in captures_str]
    if len(strs) == 0:
        return [0, 0]

    # max length > 100
    strs_len_exceed_100 = sum(1 for s in strs if len(s) > 100)

    # max length
    strs_maxlen = max(len(s) for s in strs)

    return [strs_len_exceed_100, strs_maxlen]


def extract_number_feature(root_node):
    query_num = JS_LANGUAGE.query("(number)@num")
    captures_num = query_num.captures(root_node)
    nums = [capture[0].text.decode('utf-8') for capture in captures_num]
    if len(nums) == 0:
        return 0

    hex_numbers = 0
    unicode_numbers = 0
    octal_numbers = 0
    for num in nums:
        hex_numbers += len(re.findall(r'0x[0-9A-Fa-f]+', num))
        unicode_numbers += len(re.findall(r'\\u[0-9A-Fa-f]{4}', num))
        octal_numbers += len(re.findall(r'0[0-7]+', num))
    special_numbers_count = hex_numbers + unicode_numbers + octal_numbers
    return special_numbers_count


# Function to cal average whitespace count per line
def cal_average_whitespace_count(code, lines_of_code):
    whitespace_count = len(re.findall(r'\s', code))
    return whitespace_count / lines_of_code


# Function to cal average symbol count per line
def cal_symbol_count(code):
    symbol_count = len(re.findall(r'[%$@^~\\]', code))
    return symbol_count


def get_lexical_features(js_file_path):
    lexical_features = []

    with open(js_file_path, 'r') as file:
        code = file.read()
    tree = parser.parse(bytes(code, "utf8"))
    root_node = tree.root_node

    if root_node.child_count == 0:
        return np.zeros(11, dtype=int).tolist()

    # add lexical features
    lines_of_code = root_node.end_point[0] + 1

    lexical_features.append(lines_of_code)

    lexical_features.extend(cal_compression_ratio(
        code=code, lines_of_code=lines_of_code))

    all_identifier_features = extract_all_identifier_features(root_node=root_node)
    lexical_features.extend(all_identifier_features)

    string_features = extract_string_features(
        root_node=root_node)
    lexical_features.extend(string_features)

    number_features = extract_number_feature(root_node=root_node)
    lexical_features.append(number_features)

    lexical_features.append(cal_average_whitespace_count(
        code=code, lines_of_code=lines_of_code))

    lexical_features.append(cal_symbol_count(code=code))

    if len(lexical_features) != 11:
        return None
    return lexical_features
