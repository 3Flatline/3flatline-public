```
 _____ _____ _       _   _ _               ____ _     ___ 
|___ /|  ___| | __ _| |_| (_)_ __   ___   / ___| |   |_ _|
  |_ \| |_  | |/ _` | __| | | '_ \ / _ \ | |   | |    | | 
 ___) |  _| | | (_| | |_| | | | | |  __/ | |___| |___ | | 
|____/|_|   |_|\__,_|\__|_|_|_| |_|\___|  \____|_____|___|
```                                

## Quickstart

3Flatline Dixie platform is a static code analyzing platform that works on a number of different languages: C/C++. ObjC, Golang, Java, Python, Ruby, JavaScript, PHP, and decompiled pseudo-C.  It uses a number of different methods to scan your submitted code and find potential vulnerabilities.

Sending files and creating analysis tasks are conducted through a Command Line Interface written in Python.  The CLI requires Python 3.10 or higher and can be installed through the Python Package Index or by directly downloading the files and installing the dependencies.

Account credentials are created when subscribing to a paid plan at the [3Flatline Website](https://3flatline.ai) and are emailed to the account used to purchase the subscription. Once initial credentials have been sent *YOU MUST CHANGE YOUR PASSWORD USING THE WEB GUI BEFORE YOU CAN USE THE CLI*.

Once you have credentials, the CLI can be installed by either using the Python Package Index or by directly downloading and installing the dependencies indicated in the `requirements.txt` file.  If you require additional assistance with installation see the "Installation" page from the navigation bar.

PyPI: [3Flatline PyPI](https://pypi.org/project/three-flatline-cli/) or by running `pip install three-flatline-cli`.

Github Download:[3Flatline Direct Download](https://github.com/3Flatline/3flatline-public)

## Running the CLI

- If you installed the cli from PyPI, you can run it by running the `3flatline` command.
- If you installed the cli from source, you can run it with `python3 3flatline-cli.py` command.

Note: The CLI will require you to log in before you can perform any actions.

## Commands: 
| Action | Command Example |
| -- | -- |
|Authenticate | `authenticate -u <username> -p <password>` |
|Get user token allocation | `user` |
|Estimate token cost for file/directory | `estimate <filepath for analysis>`|
|Create a job from file/folder |`create_task <filepath for analysis>`|
|Get status of all jobs | `status`|
|Search for specific status| `status -s <task_id> <task id>...`|
|List all jobs and results you have created| `list`|
|List a specific job’s info/results| `list -s <task id> <task id>...`|
|Download results| Add flag to list `-d <output filepath>`|
|Download results as markdown| Add flag to list `-m -d <output filepath>`|
|Delete task(s)| `delete <task id> <task id>...`|

The `status` command will also output all task IDs to make it easier to use with other commands.

To run any of these commands immediately on start, string them with quotes on the command line:

```python3 3flatline-cli-cmd2.py "authenticate -u <username> -p <password>" "create_task <path>" "status"```


To create multiple jobs from the cli, quote the individual commands you would like run:

```python3 3flatline-cli-cmd2.py "authenticate -u aaron@3flatline.ai -p DefNotMyPassword!" "create_task /home/user/3flatline/cli/test_file1.c" "create_task /home/user/3flatline/cli/test_file2.c"```


Keep in mind that each run of the CLI requires authentication.  The CLI will maintain a token while it is open and will refresh your authorization before each command is run, but only if you keep the CLI open.  If the CLI is closed, you will need to re-authenticate with the server.  

## Misc. Tips

- The current CLI does not have filters or search for jobs as the intent is that results are downloaded immediately after a run has completed.  This can make managing multiple jobs difficult.  The Web UI has a more user friendly interface if the number of jobs gets unmanageable in the CLI, and we recommend deleting them online in that instance.
- Jobs are retrieved by providing a task UUID, and this can make it difficult in large numbers.  Various commands have "helper tips" that are pre-formatted commands and UUIDs to make job selection easier.  For example, the `create_task` command will output a list of the created task UUIDs to copy/paste in future commands.  The `status` command will also output a list of every included UUID that was listed using that command.
- If you have written a custom integration or adjusted the CLI in a helpful way, please submit a pull request directly to this repository, and we will review it!
- 3Flatline is run by real people who are proud of what they have made. If you need assistance or have ideas for a feature, please reach out to support@3flatline.ai, and it will go to a real developer who can help.

