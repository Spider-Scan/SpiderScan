def analysis_shell_type_command(script):
    res = False
    is_malicious = script.is_malicious()
    if is_malicious:
        res = True
    return res
