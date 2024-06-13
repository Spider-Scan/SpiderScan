class Function:
    def __init__(self, package: str, file: str, name: str, qualifiedname: str, comment: str, parameters_num: int, code: str):
        self.package = package
        self.file = file
        self.name = name
        self.qualifiedname = qualifiedname
        self.comment = comment
        self.parameters_num = parameters_num
        self.code = code

    def __str__(self):
        return f"Function Instance:\n" \
               f"package: {self.package}\n" \
               f"file: {self.file}\n" \
               f"name: {self.name}\n" \
               f"qualified name: {self.qualifiedname}\n" \
               f"comment: {self.comment}\n" \
               f"parameters_num: {self.parameters_num}\n"
