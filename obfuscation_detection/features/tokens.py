"""
    Extracting syntactic units from a JavaScript file and converting them into integers.
"""

import sys
import os
import warnings
import obfuscation_detection.features.tokens2int.tree_sitter_simpl as tree_sitter_simpl
import obfuscation_detection.extract_features as extract_features

warnings.simplefilter(action='ignore', category=FutureWarning)
SRC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(SRC_PATH, 'features', 'tokens2int'))
sys.path.insert(0, os.path.join(SRC_PATH, 'tree-sitter'))

DICO_TOKENS_INT = tree_sitter_simpl.ast_units_dico


def tokens_to_numbers(input_file):
    """
        Convert a list of syntactic units in their corresponding numbers
        (as indicated in the corresponding units dictionary).

        -------
        Parameters:
        - input_file: str
            Path of the file to be analysed.
        -------
        Returns:
        - List
            Contains the Integers which correspond to the units given in tokens_list.
        - or None if tokens_list is empty (cases where the JS file considered either is no JS,
        malformed or empty).
    """

    tokens_list = extract_features.get_syntactic_units(input_file)
    # print(tokens_list)
    if isinstance(tokens_list, list) and tokens_list is not None and tokens_list != []:
        res = [DICO_TOKENS_INT.get(x, 30) for x in tokens_list]
        if len(res) != len(tokens_list):
            return None
        return res
        # return list(map(lambda x: DICO_TOKENS_INT[x], tokens_list))
    return None
