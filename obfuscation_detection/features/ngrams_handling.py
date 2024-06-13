import os
import pickle
import numpy as np
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import HashingVectorizer

import obfuscation_detection.features.tokens as tokens

CURRENT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__)))
DICO_PATH = os.path.join(CURRENT_PATH, 'ngrams2int')

# Producing n-grams from syntactical units by moving a fixed-length window to extract subsequence
# of length n.
def n_grams_list(numbers_list, n):
    if numbers_list is not None:
        len_numbers_list = len(numbers_list)
        if n < 1 or n > len_numbers_list:
            return None
        else:
            range_n = range(n)
            matrix_all_n_grams = []
            range_list = range(len_numbers_list - (n - 1))
            for j in range_list:  # Loop on all the n-grams
                matrix_all_n_grams.append(tuple(numbers_list[j + i] for i in range_n))
            return matrix_all_n_grams
    return None


# Analysing the number of occurrences (probability) of each n-gram in JavaScript files.
def count_sets_of_n_grams(input_file, tolerance, n):
    numbers_list = tokens.tokens_to_numbers(input_file)
    matrix_all_n_grams = n_grams_list(numbers_list, n)
    # Each row: tuple representing an n-gram.

    if matrix_all_n_grams is not None:
        dico_of_n_grams = {}
        # Nb of lines in the matrix, i.e. of sets of n-grams
        for j, _ in enumerate(matrix_all_n_grams):
            if matrix_all_n_grams[j] in dico_of_n_grams:
                dico_of_n_grams[matrix_all_n_grams[j]] += 1
            else:
                dico_of_n_grams[matrix_all_n_grams[j]] = 1

        return [dico_of_n_grams, len(matrix_all_n_grams)]
    return [None, None]


# Simplifying the n-grams list and mapping the resulting n-grams to integers.
def import_modules(n):
    return pickle.load(open(os.path.join(DICO_PATH, str(n) + '-gram', 'ast_treesitter_simpl'), 'rb'))


def nb_features(n):
    ns_features = [31, 961, 4000, 15000, 20000, 40000, 80000]
    if n < 8:
        n_features = ns_features[n - 1]
    else:
        n_features = 300000
    return n_features


def vect_proba_of_n_grams(input_file, tolerance, n, dico_ngram_int):
    dico_of_n_grams, nb_n_grams = count_sets_of_n_grams(input_file, tolerance, n)
    if dico_of_n_grams is not None:
        n_features = nb_features(n)
        vect_n_grams_proba = np.zeros(n_features)
        # Bigger vector on purpose, to have space for new n-grams
        for key, proba in dico_of_n_grams.items():
            map_ngram_int = n_gram_to_int(dico_ngram_int, key, n_features)
            if map_ngram_int is not None:
                vect_n_grams_proba[map_ngram_int] = proba / nb_n_grams

        return vect_n_grams_proba
    return None


def n_gram_to_int(dico_ngram_int, n_gram, n_features):
    try:
        i = dico_ngram_int[str(n_gram)]
    except KeyError:  # Key not in dico, we add it. Beware dico referenced as global variable.
        dico_ngram_int[str(n_gram)] = len(dico_ngram_int)
        i = dico_ngram_int[str(n_gram)]
    if i < n_features:
        return i
    else:
        """logging.warning('The vector space size of ' + str(n_features) + ' is too small.'
                        + ' Tried to access element ' + str(i)
                        + '. This can be changed in ngrams_handling.nb_features(n)')"""
        return None


def int_to_n_gram(dico_ngram_int, i):
    try:
        ngram = dico_ngram_int[str(i)]
        return ngram
    except KeyError as err:
        print('The key ' + str(err) + ' is not in the n-gram - int mapping dictionary')

def csr_proba_of_n_grams_hash_storage(input_file, tolerance, n, n_features):
    tokens_int = tokens.tokens_to_numbers(input_file, tolerance)
    if tokens_int is not None:
        corpus = [str(tokens_int)]
        vectorizer = HashingVectorizer(token_pattern=r"(?u)\b\w+\b", ngram_range=(n, n), norm='l1',
                                       alternate_sign=False, n_features=n_features)
        res = vectorizer.fit_transform(corpus)

        return res
    return None


def concatenate_csr_matrices(matrix1, matrix2, nb_col):
    if matrix1 is None:
        return matrix2
    elif matrix2 is None:
        return matrix1
    res = csr_matrix((matrix1.shape[0] + matrix2.shape[0], nb_col))
    res.data = np.concatenate((matrix1.data, matrix2.data))
    res.indices = np.concatenate((matrix1.indices, matrix2.indices))
    new_ind_ptr = matrix2.indptr + len(matrix1.data)
    new_ind_ptr = new_ind_ptr[1:]
    res.indptr = np.concatenate((matrix1.indptr, new_ind_ptr))
    return res
