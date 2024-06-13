"""
    Main module to classify JavaScript files using a given model.
"""

import os
import pickle
import obfuscation_detection.utility as utility
import obfuscation_detection.features.static_analysis as static_analysis


def test_model(names, labels, attributes, model, print_res=True, print_res_verbose=False,
               print_score=True, threshold=0.29):
    if isinstance(model, str):
        model = pickle.load(open(model, 'rb'))

    labels_predicted_proba_test = model.predict_proba(attributes)

    labels_predicted_test = utility. \
        predict_labels_using_threshold(len(names), labels_predicted_proba_test, threshold)

    if print_res:
        utility.get_classification_results(names, labels_predicted_test)

    if print_res_verbose:
        utility.get_classification_results_verbose(names, labels, labels_predicted_test,
                                                   labels_predicted_proba_test, model,
                                                   attributes, threshold)

    if print_score:
        utility.get_score(labels, labels_predicted_test)

    return labels_predicted_test


def classify_analysis_results(save_dir, model, threshold):
    names = pickle.load(open(os.path.join(save_dir, 'Names'), 'rb'))
    attributes = pickle.load(open(os.path.join(save_dir, 'Attributes'), 'rb'))
    labels = pickle.load(open(os.path.join(save_dir, 'Labels'), 'rb'))

    test_model(names, labels, attributes, model=model, threshold=threshold)
