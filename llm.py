from openai import OpenAI
import json
import re
from category import category_doc
import time

# add your organization here
organization = ""
# add your API key here
api_key = ''
model_3 = 'gpt-3.5-turbo-0125'

classes = """
<1> [manipulate the path] Construct the path of the file. Work with the path.
<2> [read input data from hardware devices] Create a new serial port connection. Read inputs from connected hardware devices such as keyboards, mice, and sensors.
<3> [get the path or directory information] Check whether a path exists. Read the contents of a directory. Extract information from paths.
<4> [get system information] Get information about the process, Node.js and its dependencies versions, operating system, or other system-related info. Get CPU information or memory information. Get disk information.
<5> [get user information] Get information about the user, such as the path of the current user's home directory. Get information about the currently effective user. Read data from the clipboard.
<6> [search for a file] Search for files with a specific extension or specific matching pattern. Search for a file in a given path.
<7> [copy or move a file or directory] Copy or move a file or directory from source path to the destination path.
<8> [delete a file or directory] Remove a file or directory. Delete a file or directory. Remove the symbolic link.
<9> [modify the permissions or ownership] Modify the permissions of the file. Change the ownership of the file.
<10> [create a file or directory] Create a file or directory.
<11> [read data from a byte array, or stream] Read data from streams. Read data from a buffer. Read data from another process.
<12> [read data from a file] Read the content of the file. Read bytes from the file.
<13> [write data to a byte array, or stream] Write data to the request body. Write data to the buffer. Write data to other process.
<14> [write data to a file] Write data to a file.
<15> [compress data] Compress a chunk of data. Compress a file.
<16> [decompress data] Decompress a chunk of data. Decompress a file.
<17> [create a writable stream] Create a writable stream for the purpose of writing data.
<18> [create a readable stream] Create a readable stream for the purpose of reading data.
<19> [open a file] Open a file. Open a directory for iterative scanning.
<20> [make HTTP request] Make an HTTP GET or POST request.
<21> [resolve the DNS] Resolve the IP addresses of the specified hostname. Get the IP addresses of the current server through DNS resolution.
<22> [create a network server or communication] Create a new instance of an HTTP server. Create an HTTP request object. Create a socket communication. Establish a connection to a specified server at a given port. Create a transport object for sending emails.
<23> [send data over the network] Send an email. Send data through an established network connection. Send data through FTP.
<24> [receive data over the network] Receive data from a response. Get data from a network connection. Receive data from a request.
<25> [configure the network] Set the IP address and port of servers to be used when performing DNS resolution. Set the parameters related to the network. Create a new HTML element.
<26> [get network information] Get information about the network interfaces of the computer. Get IP addresses, netmask, family, and more. Access HTML forms within a document.
<27> [start listening] Start listening for incoming connections on a specified port.
<28> [create a data representation] Create a buffer. Create a string. Generate random data or bytes. Create map or directory.
<29> [encode the data] Convert data into a string representation. Get UTF-8, hex, binary encoded characters. Encode binary data to printable ASCII characters using Base64/32/16.
<30> [decode the data] Parse a JSON string to construct a value or object. Get UTF-8, hex, binary decoded characters. Decode the Base64/32/16 encoded bytes-like object or ASCII strings.
<31> [create a cipher object] Create a cipher object which is used to cipher data. Create a Hash object.
<32> [create a decipher object] Create a decipher object which is used to decipher data.
<33> [cipher the data] Update the cipher with the text to encrypt. Encrypt the data with a specific encryption algorithm. Get the hash value.
<34> [decipher the data] Decrypt the data with a specific decryption algorithm.
<35> [spawn a new process] Spawn a new process using the given command.
<36> [run an executable file] Execute or run files.
<37> [execute a command] Spawn a shell then execute the command within that shell. Execute a command.
<38> [pipe the data] Take the data output from one stream and pass it as input to another stream. Read data from a readable stream and write it to a writable stream. Data transformation or streaming.
<39> [execute a dynamically created program] Run code represented as a string. Run the compiled code.
<40> [Others] String manipulation such splitting, substring, indexing, concatenating or padding. Iterate over array elements or dict elements. Turn or convert a string into lowercase or uppercase. Sorts elements based on a given comparison function. Get the type of a value. Add or Remove an element from array. Event binding for method based on name.
"""


def llm_classification(description):
    messages = [
        {
            "role": "system", "content": f"""
You are an expert in the field of programming, and Your task is to classify an API description into one of the following classes. Each class is uniquely identified by a number and described with a specific label and few examples that belong to the class. Based on the similarity between the description I provide and the examples for each class, determine the most appropriate class. If the description does not clearly match any given class based on the examples, or if there is uncertainty about its classification, use the default class number 40. The answer should only contain the class number and restricted to one option.

{classes} 
                    """
        },
        {
            "role": "user", "content": f"""{description}"""
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    log_content = ''
    lines = answer.splitlines()
    pattern = r'(\d+)'
    sub_type_list = []
    for line in lines:
        if '40' in line:
            sub_type_list.append('Others')
        else:
            match = re.search(pattern, line)
            if match:
                sub_type_number = match.group(1)
                if sub_type_number in category_doc.keys():
                    log_content += category_doc[sub_type_number] + ' '
                    sub_type_list.append(sub_type_number)
            else:
                sub_type_list.append('Others')
    if len(sub_type_list) == 0:
        sub_type_list.append('Others')
    return sub_type_list


def llm_classification_comment_with_code_summary(comment, code_summary):
    messages = [
        {
            "role": "system", "content": f"""
You are an expert in the field of programming, and your task is to classify the description of a API and its comment together into one of the following classes. Each class is uniquely identified by a number and described with a specific label and few examples that belong to the class. Based on the similarity between the description I provide and the examples for each class, determine the most appropriate class. If the description does not clearly match any given class based on the examples, or if there is uncertainty about its classification, use the default class number 40. The answer should only contain the class number and restricted to one option.
    
{classes} 
                        """
        },
        {
            "role": "user", "content": f"""comment:{comment}, code summary: {code_summary}"""
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    log_content = ''
    lines = answer.splitlines()
    pattern = r'(\d+)'
    sub_type_list = []
    for line in lines:
        if '40' in line:
            sub_type_list.append('Others')
        else:
            match = re.search(pattern, line)
            if match:
                sub_type_number = match.group(1)
                if sub_type_number in category_doc.keys():
                    log_content += category_doc[sub_type_number] + ' '
                    sub_type_list.append(sub_type_number)
            else:
                sub_type_list.append('Others')
    if len(sub_type_list) == 0:
        sub_type_list.append('Others')
    return sub_type_list


def llm_shell_command_interpret(shell_command):
    messages = [
        {
            "role": "system", "content": """
    You are now an experienced Linux shell programmer. I will give you a piece of shell command. make a description and only return the answer in JSON object as follows:
    {
        "Description": {
            "1": "${description 1}",
            "2": "${description 2}",
        },
        "Judgement": "${judge}",
        "File": ["${file 1}"],
       
    }
    If it contains only 1 command, explain the shell command and replace the ${description 1}. If it contains more than one command, explain each command and fill in the `description` field.
    If the shell command runs some files during the execution, such as using the command `node`, replace the ${file 1} with the file name.
    Finally make a judgement of the whole shell command, give me the answer whether the shell command I give you is malicious or not. 
    There are several malicious behaviors: 
    If the shell command retrieves user, system information, or other local data and then sends it to a specific URL or performs DNS lookup, it is malicious.
    If the shell command downloads files but does not execute them, it is benign.
    If the shell command downloads files and execute these files, it is malicious.
    If the shell command initiates a reverse shell, it is malicious.
    If the shell command uses the rm command to delete unimportant files, it is benign.
    If the shell command delete user, system related files, or delete some important files, or using 'rm -rf' to delete all files, it is malicious.
    If the shell command executes a local shell script file or another executable file, it is malicious.
    If the shell command is not a valid Linux shell command, it is benign.
    If the behavior does not fall in these cases, make judgement based on your knowledge.
    The answer of the judgement should only be malicious or benign, replace the ${judge} with the judgement. 
    Do not give me the answer beyond the JSON.
                                """
        },
        {
            "role": "user", "content": f"""{shell_command}"""
        }
    ]
    answer = connect_with_retry(messages)

    # pre process
    start_index = answer.find('{')
    end_index = answer.rfind('}')
    content_with_braces = answer[start_index: end_index + 1].strip()
    try:
        json_object = json.loads(content_with_braces)
        return json_object
    except json.JSONDecodeError:
        raise json.JSONDecodeError(f"llm shell command interpret with input: {answer} has wrong answer format")


def llm_make_assumption_from_code(code, call_name, language):
    messages = [
        {
            "role": "user",
            "content": f"""
    Given the JavaScript code: `{code}` implemented in the Node.js ecosystem, infer the behavior of the method `{call_name}` based on its name and the code itself. The output should be concise and generic, no more than 15 words. If the information cannot be determined from the code, return Unknown
                    """
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    return answer


def llm_make_assumption_from_cate_call_name(qualifier, cate, call_name):
    messages = [
        {
            "role": "user",
            "content": f"""An object created by an API exhibits the following behavior: '{cate}'. There is a method call, `{call_name}`, made on this object. Please infer the behavior of this method call based on the API's behavior and the name of the method call. Make the output as concise as possible. If you can't get any information from the call name, return Unknown"""
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    return answer


def llm_analyse_script(script):
    messages = [
        {
            "role": "system", "content": """
    You are an experienced Linux shell programmer and an experienced NodeJS package programmer. Your task is to return a JSON object consisting of key-value pairs. I will provide a JSON template, and you must follow this template, making necessary changes to the placeholders or extending it as needed.
    First, determine whether the command only use `node` or 'start' command to run some files. If so, the template for the answer is as follows:
    {
        "Type": "Node",
        "Run": ["${file-1}"]

    }
    Replace the ${file-1} with the file being run. If the command run more than one files, include them in the `run` field.
    If the command is nor related to `npm` or `node`, but related to a shell command, please output the answer below:
    {
        "Type": "Shell_Command"
    }
                                                """
        },
        {
            "role": "user", "content": f"""{script}"""
        }
    ]
    answer = connect_with_retry(messages)

    # pre process
    start_index = answer.find('{')
    end_index = answer.rfind('}')
    content_with_braces = answer[start_index: end_index + 1].strip()
    try:
        json_object = json.loads(content_with_braces)
        return json_object
    except json.JSONDecodeError:
        raise json.JSONDecodeError(f"llm_analyse_script with input: {answer} has wrong answer format")


def llm_run_executable_file(file_name):
    messages = [
        {
            "role": "system",
            "content": f"""
You are an experienced Node.js programmer. I will provide you with a string representing the parameters of an API that runs an executable file. Your task is to determine whether this API is executing potentially suspicious or malicious files. The following cases will help you make your judgment.
1. If the function runs files with extensions such as `.bat`, `.exe`, or `.sh`, the answer is Yes.
2. If the function runs a file with the format of markdown, the answer is Yes.
3. If the function runs a js file, the answer is No.
4. If the parameter string does not resemble a file, the answer is No.
5. If the behavior does not fall within these cases, make a judgment based on your knowledge.
The answer should only be Yes or No.
                            """
        },
        {
            "role": "user", "content": f"""{file_name}"""
        }
    ]

    answer = connect_with_retry(messages, model=model_3)
    if re.search(r'Yes', answer, re.IGNORECASE):
        return True
    else:
        return False


def llm_code_summary(code):
    messages = [
        {
            "role": "user",
            "content": f"""
         Give the code `{code}`, which is implemented in JavaScript and belongs to the Node.js ecosystem, Please provide a summary of the code snippet, include the main purpose of the code. Make the summary as concise as possible and no more than 10 words.
        """
        }
    ]
    answer = connect_with_retry(messages)
    return answer


def llm_execute_command_analysis(command):
    messages = [
        {
            "role": "system",
            "content": f"""
        You are an experienced Node.js programmer, I will provide you with a string representing the parameters of a command execution API. Your task is to determine whether this API performs any malicious behaviors. The following cases will help you make your judgment.
        If this shell command run a js file in a new process, the answer is Yes.
        If this shell command retrieves  user, system information, or other local data and then sends it to specific URL or performs DNS lookup, the answer is Yes.
        If the shell command downloads files but does not execute them, the answer is No.
        If the shell command downloads files and run these files, the answer is Yes.
        If the shell command initiates a reverse shell, the answer is Yes.
        If the shell command delete user, system related files, or delete some important files, or using 'rm -rf' to delete all files, the answer is Yes.
        If the shell command delete .git file in local path, it is benign.
        If the shell command just echo some information to the console, it is benign.
        If the shell command execute local shell script file such '.sh', or other executable file such as '.exe', the answer is Yes.
        If the you cannot determine whether the function is potentially malicious based on the parameter, the answer is No.
        If the behavior does not fall in these cases, make judgement based on your knowledge.
        The answer should only be Yes or No.
                        """
        },
        {
            "role": "user", "content": f"""{command}"""
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    if re.search(r'Yes', answer, re.IGNORECASE):
        return True
    else:
        return False


def llm_read_file_command_analysis(file_path):
    messages = [
        {
            "role": "system",
            "content": f"""
You are an experienced NodeJS programmer. I will provide you with a string representing the parameters of a file-reading API. Your task is to determine whether this API reads a sensitive file. The following cases will help you make your judgment.
If the function attempts to read config file of npm package such as `package.json` or other configuration files that do not contain system settings, such as `.json`, the answer is No. 
If the function attempts to read file related to the core of the `npm` or `nodejs`, such as `.npmrc` or `node.exe`, the answer is Yes. 
If the function attempts to read file in Unix-like operating system shells, such as `bash`, `zsh`, `zshrc`, the answer is Yes.
If the function attempts to access system configuration files, such as `zshrc`, `bash_history`, `zsh_history`, `/etc/ssh/ssh_config`, `C:\Windows\System32\Config`, or `/etc/hosts`, the answer is Yes.
If the function attempts to read files containing user credentials or passwords, such as `/etc/passwd`, `/etc/shadow`, or `C:\Windows\System32\Config\SAM`, the answer is Yes.
If the function tries to read private keys or certificates, such as ~/.ssh/id_rsa, /etc/ssl/private/server.key, the answer is Yes.
If the function attempts to read files from directories such as `.env`, `.svn`, or `.github`, which contain metadata or project management files for tools and platforms, the answer is Yes.
If the behavior does not fall in these cases, make judgement based on your knowledge.
The answer should only be Yes or No.
                        """
        },
        {
            "role": "user", "content": f"""{file_path}"""
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    if re.search(r'Yes', answer, re.IGNORECASE):
        return True
    else:
        return False


def llm_write_file_command_analysis(file_path):
    messages = [
        {
            "role": "system",
            "content": f"""
        You are an experienced Node.js programmer. I will provide you with a string representing the parameters of an API that wirtes data to a file. Your task is to determine whether this API writes data to sensitive file. The following cases will help you make your judgment.
        If the function writes data to a code file with a `.js` extension or to a configuration file of an npm package, such as `package.json`, the answer is No.
        If the function writes data to files in Unix-like operating system shells, such as `bash`, `zsh`, `zshrc`, the answer is Yes.
        If the function writes date to system configuration files, such as `zshrc_history`, `bash_history`, `zsh_history`, `/etc/ssh/ssh_config`, `C:\Windows\System32\Config`, or `/etc/hosts`, the answer is Yes.
        If the function writes data to the file from sensitive path in Linux or Windows, such `ssh`, `passwd`, `shadow`, `ssl`, or the path is related to core file of `npm` or `node.js`, the answer is Yes.
        If the function writes data to the root path of Linux or Windows, the answer is Yes.
        If the behavior does not fall in these cases, make judgement based on your knowledge.
        The answer should only be Yes or No.
                        """
        },
        {
            "role": "user", "content": f"""{file_path}"""
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    if re.search(r'Yes', answer, re.IGNORECASE):
        return True
    else:
        return False


def llm_suspicious_url(url: str):
    messages = [
        {
            "role": "system",
            "content": f"""
            Please evaluate the string I provide, which is the parameter for a function that creates a network server or sends data through the network, locate the URL format string, and determine if it is a suspicious URL. A URL should be considered suspicious if it exhibits any of the following attributes; otherwise, it is benign. The answer should only be suspicios or benign.
            1. Obfuscated or Shortened Links
            2. Misspelled Domain Names
            3. Unusual or Random Strings
            4. Excessive Use of Special Characters
            5. IP Addresses in the URL
            6. Presence of PII Request
            7. Reputation and History
            8. Redirection Chains
            9. Non-Standard Port Numbers
            """
        },
        {
            "role": "user", "content": f"""{url}"""
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    if re.search(r'suspicios', answer, re.IGNORECASE):
        return True
    else:
        return False


def llm_dynamically_created_program_analysis(program_string):
    messages = [
        {
            "role": "user",
            "content": f"""
    The string "{program_string}" is a code piece, give me the answer whether the code is potential malicious or not.
    The answer should be Yes or No
                    """
        }
    ]
    answer = connect_with_retry(messages, model=model_3)
    if re.search(r'Yes', answer, re.IGNORECASE):
        return True
    else:
        return False


def connect_with_retry(prompt, max_attempts=5, delay=1, model=model_3):
    LLM_client = OpenAI(organization=organization, api_key=api_key)
    attempts = 0
    while attempts < max_attempts:
        try:
            completion = LLM_client.chat.completions.create(
                model=model,
                messages=prompt,
                temperature=0.7,
                max_tokens=2048
            )
            answer = completion.choices[0].message.content
            # Attempt to establish the connection here
            if attempts > max_attempts - 1:
                raise ConnectionError("Connection failed")
            else:
                return answer

        except Exception:
            attempts += 1
            if attempts < max_attempts:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)

    # If max attempts are reached without successful connection, raise an exception
    raise ConnectionError("Failed to establish connection to OpenAI after maximum attempts")
