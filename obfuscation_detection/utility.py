import os
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix


def classifier_choice(estimators=500):
    return RandomForestClassifier(n_estimators=estimators, max_depth=50, random_state=0, n_jobs=-1)


def predict_labels_using_threshold(names_length, labels_predicted_proba, threshold):
    labels_predicted_test = ['benign' for _ in range(names_length)]
    for i, _ in enumerate(labels_predicted_test):
        if labels_predicted_proba[i, 1] >= threshold:  # If the proba of the sample being malicious
            # is over the threshold...
            labels_predicted_test[i] = 'malicious'  # ... we classify the sample as malicious.

    return labels_predicted_test


def get_classification_results_verbose(names, labels, labels_predicted, labels_predicted_proba,
                                       model, attributes, threshold):
    counts_of_same_predictions = get_nb_trees_specific_label(model, attributes,
                                                             labels, labels_predicted, threshold)
    nb_trees = len(model.estimators_)
    for i, _ in enumerate(names):
        print(str(names[i]) + ': ' + str(labels_predicted[i]) + ' ('
              + str(labels[i]) + ') ' + 'Proba: ' + str(labels_predicted_proba[i])
              + ' Majority: ' + str(counts_of_same_predictions[i]) + '/' + str(nb_trees))
    print('> Name: labelPredicted (trueLabel) Probability[benign, malicious] majorityVoteTrees')


def get_classification_results(names, labels_predicted):
    for i, _ in enumerate(names):
        print(str(names[i]) + ': ' + str(labels_predicted[i]))
    print('> Name: labelPredicted')


def get_score(labels, labels_predicted):
    if '?' in labels:
        print("No ground truth given: unable to evaluate the accuracy of the "
              + "classifier's predictions")
    else:
        try:
            tn, fp, fn, tp = confusion_matrix(labels, labels_predicted,
                                              labels=['benign', 'malicious']).ravel()
            print("Detection: " + str((tp + tn) / (tp + tn + fp + fn)))
            print("TP: " + str(tp) + ", FP: " + str(fp) + ", FN: " + str(fn) + ", TN: "
                  + str(tn))

        except ValueError as error_message:
            print(error_message)


def get_nb_trees_specific_label(model, attributes, labels, labels_predicted, threshold):
    counts_of_same_predictions = [0 for _, _ in enumerate(labels)]
    for each_tree in model.estimators_:
        single_tree_predictions_proba = each_tree.predict_proba(attributes)
        single_tree_predictions = predict_labels_using_threshold(len(labels),
                                                                 single_tree_predictions_proba,
                                                                 threshold)
        for j, _ in enumerate(single_tree_predictions):
            if single_tree_predictions[j] == labels_predicted[j]:
                counts_of_same_predictions[j] += 1

        """
        dot_data = tree.export_graphviz(each_tree, out_file=None, special_characters=True,
                                        class_names=['benign', 'malicious'], filled=True,
                                        rounded=True, proportion=True)
        graph = graphviz.Source(dot_data)
        graph.render("SingleTree-" + str(i))
        i += 1
        """

    return counts_of_same_predictions


def parsing_commands(parser):
    parser.add_argument('--t', metavar='TOLERANT', type=str, nargs=1, choices=['true', 'false'],
                        default=['false'], help='tolerates a few cases of syntax errors')
    parser.add_argument('--n', metavar='INTEGER', type=int, nargs=1, default=[4],
                        help='stands for the size of the sliding-window which goes through the '
                             + 'units contained in the files to be analyzed')
    parser.add_argument('--dnh', metavar='BOOL', type=str, nargs=1, default=['True'],
                        choices=['True', 'False'],
                        help='the n-grams are mapped to integers using a dictionary and not hashes')
    parser.add_argument('--v', metavar='VERBOSITY', type=int, nargs=1, choices=[0, 1, 2, 3, 4, 5],
                        default=[2], help='controls the verbosity of the output, from 0 (verbose) '
                                          + 'to 5 (less verbose)')

    return parser


def save_analysis_results(save_dir, names, attributes, labels):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    pickle.dump(names, open(os.path.join(save_dir, 'Names'), 'wb'))
    pickle.dump(attributes, open(os.path.join(save_dir, 'Attributes'), 'wb'))
    pickle.dump(labels, open(os.path.join(save_dir, 'Labels'), 'wb'))

    print('The results of the analysis have been successfully stored in ' + save_dir)
