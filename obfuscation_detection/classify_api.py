from obfuscation_detection.classifier import test_model
import obfuscation_detection.features.static_analysis as static_analysis
import contextlib
import io


def classify_api(js_file, model, ngrams, threshold=0.7):
    with io.StringIO() as buf, contextlib.redirect_stdout(buf):
        names, attributes, labels = static_analysis.main_analysis(js_dirs=None, labels_dirs=None, n=ngrams,
                                                                  js_files=[js_file], labels_files=None,
                                                                  tolerance=False, training=False)

        res = None
        if names:
            res = test_model(names, labels, attributes, model=model,
                             threshold=threshold, print_res=False, print_score=False)[0]
    return res
