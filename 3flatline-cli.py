import base64
import boto3
import botocore
import cmd2
from cmd2.table_creator import (
    Column,
    SimpleTable,
)
import datetime
import gotrue.errors
import hashlib
import hmac
import json
import logging
import os
import pyfiglet
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from supabase import create_client, Client
import sys
import tiktoken
from typing import List

CLI_VERSION = "v1.2"

C_MODEL_ENDINGS = [
    ".c",
    ".cc",
    ".cpp",
    ".m",
]
APPSEC_MODEL_ENDINGS = [".php", ".go", ".py", ".rb", ".js", ".java", ".html"]
MAX_FILE_UPLOAD_SIZE = 1024 * 1024 * 10
# DEV
# API_URL_BASE = "https://krjndzi2kb.execute-api.us-east-1.amazonaws.com/v1/"
# PROD
API_URL_BASE = 'https://api.3flatline.ai/v1'

POSTGRES_PUBLIC_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imh1bXFwempucnFuY2pwZmRydGhxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDM4NTkxMzQsImV4cCI6MjAxOTQzNTEzNH0.y0DIlnd6Eg4ZtC2ieTzoa9102klz8hkXWUjpWpMNHIs'
POSTGRES_URL = "https://humqpzjnrqncjpfdrthq.supabase.co"
supabase: Client = create_client(POSTGRES_URL, POSTGRES_PUBLIC_KEY)
logging.disable(sys.maxsize)

class ThreeFlatlineCLIApp(cmd2.Cmd):
    auth_parser = cmd2.Cmd2ArgumentParser()
    auth_parser.add_argument("-u", "--username")
    auth_parser.add_argument("-p", "--password")

    list_parser = cmd2.Cmd2ArgumentParser()
    list_parser.add_argument(
        "-s",
        "--search",
        nargs="*",
        help="List only specific task ID(s) information",
        default=False,
    )
    list_parser.add_argument(
        "-m",
        "--markdown",
        action="store_true",
        help="Change cmd2 format to markdown (requires -d, otherwise ignored)",
        default=False,
    )
    list_parser.add_argument(
        "-d",
        "--download",
        nargs=1,
        help="Download the results to specific file path",
        default=False,
    )

    status_parser = cmd2.Cmd2ArgumentParser()
    status_parser.add_argument(
        "-s",
        "--search",
        nargs="*",
        help="Get status for only specific task ID(s)",
        default=False,
    )

    task_parser = cmd2.Cmd2ArgumentParser()
    task_parser.add_argument("filepath", help="Filepath to upload for scan")

    delete_parser = cmd2.Cmd2ArgumentParser()
    delete_parser.add_argument(
        "task_ids", nargs="*", help="Delete task(s) from the database"
    )

    user_parser = cmd2.Cmd2ArgumentParser()

    estimate_parser = cmd2.Cmd2ArgumentParser()
    estimate_parser.add_argument(
        "filepath", help="Filepath or directory to estimate token cost for analysis"
    )

    """A simple cmd2 application."""

    def __init__(self):
        super().__init__()
        ascii_banner = pyfiglet.figlet_format("3Flatline CLI")
        self.poutput(f"CLI Version: {CLI_VERSION}")
        self.auth_info = {}
        self.register_postloop_hook(self.logout_supabase)
        self.poutput(ascii_banner)
        self.hidden_commands.append("alias")
        self.hidden_commands.append("edit")
        self.hidden_commands.append("macro")
        self.hidden_commands.append("run_pyscript")
        self.hidden_commands.append("run_script")
        self.hidden_commands.append("shell")
        self.hidden_commands.append("shortcuts")
        self.supabase = False
        self.intro = """Welcome to the 3Flatline CLI!

This CLI interfaces with the 3Flatline servers to queue and retrieve analysis jobs.

Before creating a job or trying to find a previously started job, you'll need to authenticate with your provided credentials.

Examples of the main commands are:
    Authenticate: 'authenticate -u <username> -p <password>'
    Get user token limits: 'user'
    Estimate token cost: 'estimate <file or directory path for analysis>'
    Create a job: 'create_task <file or directory path for analysis>'
    Show the status of all tasks created: 'status'
    Show a specific job('s) status: 'status -s <task id> <task id> ...'
    List all jobs you have created and their result data: 'list'
    List a specific job's info/results: 'list -s <task id> <task id> ...'
    Download results: Add flag '-d <output filepath>' to list
    Download results as markdown: Add flags '-m -d <output filepath>' to list
    Delete a task: 'delete <task id for deletion> <task id for deletion> ...'

To run any of these commands immediately on start, string them with quotes on the command line:
python3 3flatline-cli-cmd2.py "authenticate -u <username> -p <password>" "create_task <path>" "list"
        
"""  # noqa: E501

        # Show this as the prompt when asking for input
        self.prompt = "Dix > "

    def logout_supabase(self) -> None:
        """Log out of supabase."""
        try:
            self.poutput("“Miami, joeboy, quick study.”")

        except Exception:
            pass

    @cmd2.with_argparser(auth_parser)
    def do_authenticate(self, args):
        """Authenticate with the server using your provided credentials."""
        # Todo: timeout and reauth
        # initially set to False in init
        self.supabase: Client = create_client(POSTGRES_URL, POSTGRES_PUBLIC_KEY)
        try:
            data = self.supabase.auth.sign_in_with_password(
                {"email": args.username,
                "password": args.password}
            )
            supabase.postgrest.auth(data.session.access_token)

        except gotrue.errors.AuthApiError as exc:
            self.poutput(
                f"Error encountered during login: {type(exc).__name__}: {str(exc)}"
            )
            self.poutput(
                "If this is repeated or unexpected, please contact support@3flatline.ai"
            )
            return
        # TODO: Check for message needing verification or password change or something.
        access_token = data.session.access_token
        refresh_token = data.session.refresh_token
        self.auth_info = {
            "auth_token": access_token,
            "refresh_token": refresh_token,
        }
        self.poutput("Log in success")

    def calculateSecretHash(self, client_id, client_secret, username):
        key = bytes(client_secret, "utf-8")
        message = bytes(f"{username}{client_id}", "utf-8")
        return base64.b64encode(
            hmac.new(key, message, digestmod=hashlib.sha256).digest()
        ).decode()

    def refresh_auth(self):
        """Refresh authentication with the server."""
        if not self.supabase:
            self.poutput("No login credentials found. Have you authenticated already?")
            return
        data = self.supabase.auth.refresh_session()
        self.auth_info = {
            "auth_token": data.session.access_token,
            "refresh_token": data.session.refresh_token,
        }

    def check_response_error(self, response, expected_code=None) -> bool:
        """Check and output information for an error repsonse."""
        # print(type(response.status_code))
        # print(response.content)
        if expected_code:
            if response.status_code == expected_code:
                return True
            else:
                return False
        if response.status_code == 200:
            return True
        if response.status_code == 401:
            self.poutput(
                "ERROR: received 'Unauthorized' message.  Have you authenticated to the server?"
            )
            self.poutput(
                "To authenticate try the command: authenticate -u <username> -p <password>"
            )
            return False
        if response.status_code == 403:
            if "token" in str(response.content):
                self.poutput(
                    "ERROR: Estimated token length of file exceeds monthly available token limit."
                )
            elif "length exceeds maximum file size." in str(response.content):
                self.poutput(
                    "ERROR: Estimated token length of file exceeds maximum file size."
                )
            else:
                self.poutput(
                    "ERROR: Your account is not authorized to conduct this action."
                )
                self.poutput(response.content)
            return False
        self.poutput(f"Error encountered: result status code was {response.status_code} and content {response.content}")
        return False

    @cmd2.with_argparser(task_parser)
    def do_create_task(self, args):
        """Create a new code scanning task"""
        self.refresh_auth()
        paths_to_analyze = []
        if os.path.isdir(args.filepath):
            self.poutput("Filepath provided was a directory, searching for files.")
            paths_to_analyze = self.build_file_list(args.filepath)
            if not paths_to_analyze:
                self.poutput(
                    "Provided directory does not include any files to analyze."
                )
                return
        else:
            paths_to_analyze.append(args.filepath)
        self.poutput("Creating tasks to analyze:")
        for entry in paths_to_analyze:
            self.poutput(f" -- {entry}")
        created_tasks = []
        retry_paths = []
        with requests.session() as session:
            retry_strategy = Retry(
                total=5,
                backoff_factor=2,
                status_forcelist=[500, 502, 503, 504],
            )
            session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
            for entry in paths_to_analyze:
                # Do some common sense checks first
                # Access Check
                if not os.access(entry, os.R_OK):
                    self.poutput(
                        f"* Error: Skipping file, no read access for file at {entry} *"
                    )
                    continue
                filesize = os.path.getsize(entry)
                # Filesize check
                if filesize > MAX_FILE_UPLOAD_SIZE:
                    self.poutput(
                        (
                            f"* Error: File size of {entry} is greater than max allowed file size of"
                            f" {MAX_FILE_UPLOAD_SIZE} bytes. Skipping."
                        )
                    )
                    continue
                elif filesize == 0:
                    self.poutput(
                        f"* Error: File size of {entry} is zero bytes. Skipping."
                    )
                    continue
                models = []
                for ending in C_MODEL_ENDINGS + APPSEC_MODEL_ENDINGS:
                    if entry.endswith(ending):
                        if ending in C_MODEL_ENDINGS:
                            models = ["c-firmware"]
                            break
                        elif ending in APPSEC_MODEL_ENDINGS:
                            models = ["AppSec"]
                            break
                if not models:
                    self.poutput(
                        f"File at {entry} had unsupported file extension. Skipping."
                    )
                    continue
                try:
                    with open(entry, "r") as object_file:
                        encoding = tiktoken.get_encoding("cl100k_base")
                        token_estimate = 0
                        for line in object_file.readlines():
                            token_estimate += len(encoding.encode(line))
                        self.poutput(f"Estimated file token length: {token_estimate}")
                except FileNotFoundError:
                    self.poutput(
                        f"Couldn't find {entry}, verify the file exists and path is correct."
                    )
                    return
                result = session.post(
                    f"{API_URL_BASE}/tasks",
                    headers={
                        "Authorization": self.auth_info.get("auth_token"),
                        # "x-api-key": self.auth_info.get("user_api_key"),
                        "cli_version": CLI_VERSION,
                    },
                    json={
                        "filepath": entry,
                        "token_estimate": token_estimate,
                    },
                )
                # self.poutput(result)
                if (
                    result.status_code == 403
                    and "length exceeds maximum file size." in str(result.content)
                ):
                    self.poutput(
                        "ERROR: Estimated token length of file exceeds maximum file size.  Skipping."
                    )
                    continue
                elif not self.check_response_error(result):
                    self.poutput("Error during task creation on AWS server.")
                    # self.poutput(result.status_code)
                    # self.poutput(result.content)
                    break
                result_json = result.json()
                # body = result_json.get("body")
                # self.poutput(body)
                new_task_id = result_json.get("task_id")
                signed_url = result_json.get("signed_url")
                if not new_task_id:
                    self.poutput(f"Error uploading {entry}, task not submitted.")
                    retry_paths.append(entry)
                    continue
                self.poutput(
                    f"Created task entry in database for task id: {new_task_id}, uploading for analysis."
                )
                # converted_result = result.json()
                # s3_auth_data = converted_result["url_info"]
                # headers = s3_auth_data.get("fields")
                try:
                    with open(entry, "r") as object_file:
                        response = session.put(
                            signed_url,
                            files={"file": object_file},
                        )
                        # self.poutput(response.status_code)
                        # self.poutput(response.content)
                        if self.check_response_error(response, expected_code=200):
                            self.poutput("Successfully uploaded file to server.")
                        else:
                            self.poutput(
                                "Error uploading to server, delete task entry and try again with full path."
                            )
                            self.poutput(
                                f"To delete task entry run: delete {new_task_id}"
                            )
                            return
                except FileNotFoundError:
                    self.poutput(
                        f"Couldn't find {entry}, verify the file exists and path is correct."
                    )
                    return
                # Kick off analysis
                result = requests.post(
                        f"{API_URL_BASE}/tasks/{new_task_id}",
                        headers={
                            "Authorization": self.auth_info.get("auth_token"),
                            "cli_version": CLI_VERSION,
                        },
                    )
                # self.poutput(result.status_code)
                # self.poutput(result.content)
                if not self.check_response_error(result):
                    self.poutput("Error during activation of task.")
                    # self.poutput(result.status_code)
                    # self.poutput(result.content)
                    continue
                created_tasks.append(new_task_id)
        if not created_tasks:
            self.poutput("No tasks created.")
            return

        self.poutput("Task(s) created and file(s) sent to server.  New task ids:")
        for entry in created_tasks:
            self.poutput(f" -- {entry}")

        self.poutput("To get the status of a running task use: status -s <uuid>")
        self.poutput(
            f'To get the status of all results of this run: status -s {" ".join(created_tasks)}'
        )
        self.poutput(
            "To get full data instead of status, relace 'status' with 'list' in above format"
        )
        if retry_paths:
            self.poutput(
                "Tasks were not created for the following files due to errors in uploading or task creation:"
            )
            for entry in retry_paths:
                self.poutput(f" -- {entry}")

    @cmd2.with_argparser(list_parser)
    def do_list(self, args) -> None:
        """List all code scanning tasks in your account (-s for search by task id)"""

        if args.search:
            result_list = []
            length = len(args.search)
            for i in range(0, length, 20):
                data, count = self.supabase.table('tasks').select("*").in_('task_id', args.search[i:i+20]).execute()
                result_list.extend(data[1])
        else:
            data, count = self.supabase.table('tasks').select("*").execute()
            result_list = data[1]
        if not result_list:
            self.poutput("No existing tasks to pull status for.")
            return

        self.poutput("Results:")
        self.poutput(json.dumps(result_list, indent=5))
        if args.download:
            if args.markdown:
                markdown_string = ""
                for item in result_list:
                    markdown_string += self.format_markdown(item)
                with open(args.download[0], "w") as f:
                    f.write(markdown_string)
            else:
                with open(args.download[0], "w") as f:
                    f.write(json.dumps(result_list, indent=5))
            return
        self.poutput(
            "To save this data, add '-d <filepath>' for json and '-m -d <filepath>' for markdown"
        )

    @cmd2.with_argparser(delete_parser)
    def do_delete(self, args) -> None:
        self.poutput(f'Deleting tasks: {args.task_ids}')
        """Delete as task from the database by task id"""
        result = self.supabase.table('tasks').delete().in_('task_id', args.task_ids).execute()
        # TODO: Add summary and error checks
        # print(result)

    @cmd2.with_argparser(user_parser)
    def do_user(self, args) -> None:
        """Retrieve user info for logged in user."""
        with requests.session() as session:
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[502, 503, 504],
            )
            session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
            self.refresh_auth()
            result = session.get(
                f"{API_URL_BASE}/user",
                headers={
                    "Authorization": self.auth_info.get("auth_token"),
                    "cli_version": CLI_VERSION,
                },
            )
            result_json = result.json()
            # print(result_json)
            if not self.check_response_error(result):
                return
            for key, value in result_json.items():
                if key == "cognito_userid":
                    continue
                self.poutput(f"{key}: {value}")

    @cmd2.with_argparser(estimate_parser)
    def do_estimate(self, args) -> None:
        """Retrieve user info for logged in user."""
        paths_to_analyze = []
        total_run_token_cost = 0
        if os.path.isdir(args.filepath):
            self.poutput("Filepath provided was a directory, searching for files.")
            paths_to_analyze = self.build_file_list(args.filepath)
            if not paths_to_analyze:
                self.poutput(
                    "Provided directory does not include any files to analyze."
                )
                return
        else:
            paths_to_analyze.append(args.filepath)
        for entry in paths_to_analyze:
            if not os.access(entry, os.R_OK):
                self.poutput(
                    f"* Error: Skipping file, no read access for file at {entry} *"
                )
                continue
            filesize = os.path.getsize(entry)
            # Filesize check
            if filesize > MAX_FILE_UPLOAD_SIZE:
                self.poutput(
                    (
                        f"* Error: File size of {entry} is greater than max allowed file size of"
                        f" {MAX_FILE_UPLOAD_SIZE} bytes. Skipping."
                    )
                )
                continue
            elif filesize == 0:
                self.poutput(f"* Error: File size of {entry} is zero bytes. Skipping.")
                continue
            models = []
            for ending in C_MODEL_ENDINGS + APPSEC_MODEL_ENDINGS:
                if entry.endswith(ending):
                    if ending in C_MODEL_ENDINGS:
                        models = ["c-firmware"]
                        break
                    elif ending in APPSEC_MODEL_ENDINGS:
                        models = ["AppSec"]
                        break
            if not models:
                self.poutput(
                    f"File at {entry} had unsupported file extension. Skipping."
                )
                continue
            try:
                with open(entry, "r", encoding="utf-8") as object_file:
                    encoding = tiktoken.get_encoding("cl100k_base")
                    token_estimate = 0
                    for line in object_file.readlines():
                        token_estimate += len(encoding.encode(line))
                    total_run_token_cost += token_estimate
            except FileNotFoundError:
                self.poutput(
                    f"Couldn't find {entry}, verify the file exists and path is correct. Skipping."
                )
                continue
            self.poutput(f"Estimated token cost for {entry}: {token_estimate}")
        if len(paths_to_analyze) > 1:
            self.poutput(
                f"Total estimated token cost for {args.filepath}: {total_run_token_cost}"
            )

    def format_markdown(self, result_dict) -> str:
        self.poutput("Converting to markdown.")
        task_id = result_dict.get("id")
        self.convert_list_markdown(result_dict.get("models"))
        filepath = result_dict.get("filepath")
        created_time = result_dict.get("created_time")
        results = result_dict.get("results")
        # There are two scenarios we need to check for.
        # 1) if run isn't finished, no entry in results or it is a string.
        # 2) if run is finished, could be string or list, but list might have "None" if no bugs.
        description = ""
        markdown_vuln_string = ""
        if isinstance(results, list) and results:
            result_entry = results[0]
            if result_entry:
                description = result_entry.get("code_description")
                split_description = description.split("Code Description:")
                if len(split_description) > 1:
                    description = split_description[1]
                bugs_list = result_entry.get("bugs")
                if bugs_list:
                    for entry in bugs_list:
                        markdown_vuln_string+=f"{entry}\n"
        markdown_string = f"""# {task_id}

| Field | Content |
| --- | ----------- |
| Filepath | {filepath} |
| Task Submitted | {created_time} |

## Code Description

{description}

## Vulnerabilities Detected: 

{markdown_vuln_string}

"""
        return markdown_string

    def convert_list_markdown(self, list_to_convert) -> str:
        converted_string = ""
        if list_to_convert:
            for entry in list_to_convert:
                converted_string += f"- {entry}<br>"
            return converted_string[:-4]
        else:
            return ""

    def build_file_list(self, directory) -> list:
        """Recursively build a list of files in a directory."""
        file_list = []
        with os.scandir(directory) as opened_dir:
            for entry in opened_dir:
                if not entry.name.startswith("."):
                    if entry.is_file():
                        file_list.append(entry.path)
                    elif entry.is_dir():
                        new_list = self.build_file_list(entry.path)
                        if new_list:
                            file_list.extend(new_list)
        return file_list

    @cmd2.with_argparser(status_parser)
    def do_status(self, args) -> None:
        """List status of all code scanning tasks in your account (-s for search by task id)"""
        self.refresh_auth()
        if args.search:
            result_list = []
            length = len(args.search)
            for i in range(0, length, 20):
                data, count = self.supabase.table('tasks').select("task_id, filepath, created_at, status").in_('task_id', args.search[i:i+20]).execute() 
                result_list.extend(data[1])
        else:
            data, count = self.supabase.table('tasks').select("task_id, filepath, created_at, status").execute()
            result_list = data[1]
        if not result_list:
            self.poutput("No existing tasks to pull status for.")
            return
        # self.poutput(result_list)
        table_data = []
        task_id_list = []
        for entry in result_list:
            if not entry:
                continue
            table_data.append(
                [
                    entry.get("task_id"),
                    entry.get("filepath"),
                    entry.get("created_at"),
                    entry.get("status"),
                ]
            )
            task_id_list.append(entry.get("task_id"))

        def created_time_lambda(x):
            return x[2]

        table_data.sort(key=created_time_lambda)
        columns: List[Column] = list()
        columns.append(Column("Task ID", width=36))
        columns.append(Column("Filepath", width=38))
        columns.append(Column("Created", width=15))
        columns.append(Column("Status", width=10))

        st = SimpleTable(columns)
        table = st.generate_table(table_data)
        self.poutput(table)
        list_output = ""
        for task_id in task_id_list:
            list_output += task_id + " "
        self.poutput(
            f"Task ids from this command for use in other commands: {list_output}"
        )

    def do_quit(self, *args):
        """Exit the application"""
        try:
            self.supabase.auth.sign_out()
        except AttributeError as exc:
            pass

        return super().do_quit(*args)



def main():
    """Main"""

    flatline_app = ThreeFlatlineCLIApp()
    return flatline_app.cmdloop()


if __name__ == "__main__":
    sys.exit(main())
