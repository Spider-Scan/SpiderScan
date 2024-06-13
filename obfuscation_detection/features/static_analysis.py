import os
import sys
import pickle
import obfuscation_detection.features.ngrams_handling as ngrams_handling
from obfuscation_detection.extract_features import *

CURRENT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__)))
DICO_PATH = os.path.join(CURRENT_PATH, 'ngrams2int')


def main_analysis(js_dirs, js_files, labels_files, labels_dirs, n, tolerance, training=True):
    global_ngram_dict = None
    if js_dirs is None and js_files is None:
        print('Please, indicate a directory or a JS file to be studied')

    else:

        global_ngram_dict = ngrams_handling.import_modules(n)

        if js_files is not None:
            files2do = js_files
            if labels_files is None:
                labels_files = ['?' for _, _ in enumerate(js_files)]
            labels = labels_files
        else:
            files2do, labels = [], []
        if js_dirs is not None:
            i = 0
            if labels_dirs is None:
                labels_dirs = ['?' for _, _ in enumerate(js_dirs)]
            for cdir in js_dirs:
                for cfile in os.listdir(cdir):
                    files2do.append(os.path.join(cdir, cfile))
                    if labels_dirs is not None:
                        labels.append(labels_dirs[i])
                i += 1

        tab_res = [[], [], []]

        for j, _ in enumerate(files2do):
            try:

                res = ngrams_handling.vect_proba_of_n_grams(files2do[j], tolerance, n, global_ngram_dict)
                if res is not None:
                    lexical_features = np.array(get_lexical_features(files2do[j]))
                else:
                    lexical_features = None
            except Exception as e:
                res = None
                lexical_features = None
                print("Error processing when extracting features:", files2do[j], "\n", e)

            if lexical_features is None:
                res = None
            elif res is not None:
                res = np.concatenate((lexical_features, res), axis=0)
            if res is not None:
                tab_res[0].append(files2do[j])
                tab_res[1].append(res)

                if labels and labels != []:
                    tab_res[2].append(labels[j])

        if training:
            print("saving new ngram to int dict")
            sys.path.insert(0, os.path.join(DICO_PATH, str(n) + '-gram'))
            pickle.dump(global_ngram_dict,
                        open(os.path.join(DICO_PATH, str(n) + '-gram', 'ast_treesitter_simpl'), 'wb'))

        return tab_res
