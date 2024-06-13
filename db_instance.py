import pymysql

# For ease of deployment and data constraints, we provide data in CSV format. You can create tables based on your local database engine and set the corresponding connection parameters
host = ''
port = 8080
db = ''
user = ''
password = ''


class DatabaseConnection:
    def __init__(self, loc: str):
        self.loc = loc
        self.placeholder = '%s'
        self._connection = pymysql.connect(host=host, port=port, db=db, user=user, password=password)

    def close(self):
        if self._connection:
            self._connection.close()

    def test(self):
        cursor = self._connection.cursor()
        query = "SELECT * FROM npm_builtin WHERE package = %s"
        args = 'os'
        cursor.execute(query, (args,))
        res = cursor.fetchall()
        print(res)

    def package_in_builtin(self, package, eco):
        """
        whether the given package in builtin
        """
        cursor = self._connection.cursor()
        query = f"""
            SELECT * FROM {eco}_builtin WHERE package = {self.placeholder}
        """
        cursor.execute(query, package)
        rows = cursor.fetchall()
        return rows

    def package_in_third_part(self, package, eco):
        """
        whether the given package is third-part
        """
        cursor = self._connection.cursor()
        query = f"""
            SELECT * FROM {eco}_third WHERE package = {self.placeholder}
        """
        cursor.execute(query, package)
        rows = cursor.fetchall()
        return rows

    def query(self, ecosystem, cat, *args):
        """
        search from database
        :param ecosystem: npm or pypi
        :param cat: builtin, code, third
        :param args: varied parameters
        :return: query rows
        """
        cursor = self._connection.cursor()
        query_command = f"""
            SELECT * FROM {ecosystem}_{cat} WHERE 
        """

        # Checking the number of provided parameters
        if len(args) % 2 != 0:
            raise ValueError("Invalid number of parameters. Each column must have a corresponding value.")

        # Constructing the conditions based on parameters
        conditions = []
        value_list = []
        for i in range(0, len(args), 2):
            column = args[i]
            value = args[i + 1]
            conditions.append(f"""{column} = {self.placeholder} """)
            value_list.append(value)

        # Joining the conditions with 'AND'
        query_command += " AND ".join(conditions)
        if len(value_list) == 1:
            cursor.execute(query_command, (value_list[0]))
        else:
            cursor.execute(query_command, (value_list[0], value_list[1]))
        rows = cursor.fetchall()
        return rows

    def update(self, ecosystem, cat, id, column_name, value):
        """
        update the database based on the id
        :param ecosystem: npm or pypi
        :param cat: builtin, code, third
        :param id: id
        :param column_name:
        :param value:
        """

        cursor = self._connection.cursor()
        update_query = f"""
            UPDATE  {ecosystem}_{cat}
            SET {column_name} = {self.placeholder}
            WHERE id = {self.placeholder} 
        """
        cursor.execute(update_query, (value, id))
        self._connection.commit()

    def insert(self, ecosystem, cat, qualifier, name, qualifiedname, category, summary):
        cursor = self._connection.cursor()
        insert_query = f'''
                INSERT INTO {ecosystem}_{cat} (package, name, qualifiedname, category, summary)
                VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})
            '''
        data = (qualifier, name, qualifiedname, category, summary)
        cursor.execute(insert_query, data)
        self._connection.commit()

    def insert_code(self, ecosystem, code, category, summary):
        """
        insert into code table
        :param ecosystem: npm or pypi
        :param code: code
        :param category: category
        :param summary: summary
        """
        cursor = self._connection.cursor()
        insert_query = f'''
            INSERT INTO {ecosystem}_code (code, category, summary)
            VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder})
        '''

        data = (code, category, summary)
        cursor.execute(insert_query, data)
        self._connection.commit()

    def to_db(self, package, file, name, qualifiedname, comment, parameters_num, code, table_name):
        cursor = self._connection.cursor()
        cursor.execute(
            f"""
            INSERT INTO {table_name}(package, file, name, qualifiedname, comment, parameters_num, code)
            VALUES ({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder})
        """,
            (
                package,
                file,
                name,
                qualifiedname,
                comment,
                parameters_num,
                code
            ),
        )
        self._connection.commit()

    def function_of_the_module(self, ecosystem, package, function, cat):
        cursor = self._connection.cursor()
        query = f"""
            SELECT * FROM {ecosystem}_{cat} WHERE package = {self.placeholder} and name = {self.placeholder}
        """
        cursor.execute(query, (package, function))
        rows = cursor.fetchall()
        return rows
