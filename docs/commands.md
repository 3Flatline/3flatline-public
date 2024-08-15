# CLI Commands: 

The Command Line Interface is the primary way to interact with the Dixie code scanning platform.  When starting the CLI, you will be prompted by the following interface:

```
CLI Version: v1.1
 _____ _____ _       _   _ _               ____ _     ___ 
|___ /|  ___| | __ _| |_| (_)_ __   ___   / ___| |   |_ _|
  |_ \| |_  | |/ _` | __| | | '_ \ / _ \ | |   | |    | | 
 ___) |  _| | | (_| | |_| | | | | |  __/ | |___| |___ | | 
|____/|_|   |_|\__,_|\__|_|_|_| |_|\___|  \____|_____|___|
                                                          

Welcome to the 3Flatline CLI!

This CLI interfaces with the 3Flatline servers to queue and retrieve analysis jobs.

Before creating a job or trying to find a previously started job, you'll need to authenticate with your provided credentials.

Examples of the main commands are:
    Authenticate: 'authenticate -u <username> -p <password>'
    Get user token limits: 'user'
    Estimate token cost: 'estimate <file or directory path for analysis>'
    Create a job: 'create_task <file or directory path for analysis>'
    Generate fixes for vulns: 'create_task -f <file or directory path for analysis>'
    Generate tests for vulns: 'create_task -t <file or directory path for analysis>'
    Show the status of all tasks created: 'status'
    Show a specific job('s) status: 'status -s <task id> <task id> ...'
    List all jobs you have created and their result data: 'list'
    List a specific job's info/results: 'list -s <task id> <task id> ...'
    Download results: Add flag '-d <output filepath>' to list
    Download results as markdown: Add flags '-m -d <output filepath>' to list
    Delete a task: 'delete <task id for deletion> <task id for deletion> ...'

To run any of these commands immediately on start, string them with quotes on the command line:
python3 3flatline-cli-cmd2.py "authenticate -u <username> -p <password>" "create_task <path>" "list"
        

Dix > 
```

The CLI is written in Python using the cmd2 package, and as a result it can provide help or hints using the `help` command or `-h` flag after commands.  For example, if you wanted assistance in general you can type:

```Dix > help

Documented commands (use 'help -v' for verbose/'help <topic>' for details):
===========================================================================
authenticate  delete    help     list  set     user
create_task   estimate  history  quit  status
```

Or:

```Dix > help -v

Documented commands (use 'help -v' for verbose/'help <topic>' for details):
======================================================================================================
authenticate          Authenticate with the server using your provided credentials.                   
create_task           Create a new code scanning task                                                 
delete                Delete as task from the database by task id                                     
estimate              Retrieve user info for logged in user.                                          
help                  List available commands or provide detailed help for a specific command         
history               View, run, edit, save, or clear previously entered commands                     
list                  List all code scanning tasks in your account (-s for search by task id)         
quit                  Exit this application                                                           
set                   Set a settable parameter or show current settings of parameters                 
status                List status of all code scanning tasks in your account (-s for search by task   
                      id)                                                                             
user                  Retrieve user info for logged in user. ```

Or for assistance with the format of specific commands:
```Dix > create_task -h
Usage: create_task [-h] filepath

Create a new code scanning task

positional arguments:
  filepath    Filepath to upload for scan

optional arguments:
  -h, --help  show this help message and exit
```

## Command Descriptions


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


Keep in mind that each run of the CLI requires authentication.  The CLI will maintain a token while it is open and will refresh your authorization before each command is run, but only if you keep the CLI open.  If the CLI is closed, you will need to re-aauthenticate with the server.  

## Authenticate

The `authenticate` command is used to authenticate with the remote server using your unique account credentials.  It is required at the start of every new session of the CLI as authorization tokens are not stored in between CLI runs.  In order to authenticate you follow the following pattern:

```Dix > authenticate -h
Usage: authenticate [-h] [-u USERNAME] [-p PASSWORD]

Authenticate with the server using your provided credentials.

optional arguments:
  -h, --help            show this help message and exit
  -u, --username USERNAME
  -p, --password PASSWORD
```

Example:
```authenticate -u demo@3flatline.ai -p DefNotThePassword!```

## User

The `user` command will provide information on the currently logged in user such as available tokens and your current plan.

```Dix > user
plan_tokens: 50000
tokens_available: 50000
email: demo@3flatline.ai
model_access: ['GPT3.5', 'GPT4']
tokens_used_month: 0
current_plan: Free Trial
tokens_used_lifetime: 0
```

This command is how you should keep track of your available tokens if you are on a plan with limited token amounts.

## Estimate

The `estimate` command provides an estimate of the token cost of analyzing a specific file or directory. The required filepath parameter can be either an absolute or relative path to the desired file or directory.  In the event you pass a directory path, the CLI will navigate the directory structure and estimate the cost for each supported file type found while traversing the directory.  It will list the individual token cost for each file as well as a cumulative cost for every file if passing a directory.

```
Usage: estimate [-h] filepath

Retrieve user info for logged in user.

positional arguments:
  filepath    Filepath or directory to estimate token cost for analysis

optional arguments:
  -h, --help  show this help message and exit
```

Example:
```Dix > estimate ../3flatline-demo-files
Filepath provided was a directory, searching for files.
Estimated token cost for ../3flatline-demo-files/process_image_diss.c: 6258
Estimated token cost for ../3flatline-demo-files/JndiManager.java: 2825
Estimated token cost for ../3flatline-demo-files/imgRead_socket.c: 964
File at ../3flatline-demo-files/output.md had unsupported file extension. Skipping.
File at ../3flatline-demo-files/imgRead had unsupported file extension. Skipping.
Estimated token cost for ../3flatline-demo-files/wemo-openwrt-add-header.c: 1042
Estimated token cost for ../3flatline-demo-files/tb_native_host_interface.c: 6728
File at ../3flatline-demo-files/imgRead.rzdb had unsupported file extension. Skipping.
Total estimated token cost for ../3flatline-demo-files: 17817
```

## Create Task

The `create_task` command is used to start an analysis task.  The required filepath parameter can be either a absolute or relative path to the desired file or directory.  In the event you pass a directory path, the CLI will navigate the path and submit tasks for each supported file type found while traversing the directory.

The default behavior is to only create tasks that find vulnerabilities.  If you would also like to generate fixes for vulnerabilities that are found, and/or test code that demonstrates how to determine how the vulnerability can be triggered, the `-f` and `-t` flags can be used.

```Dix > create_task -h
Usage: create_task [-h] filepath

Create a new code scanning task

positional arguments:
  filepath    Filepath to upload for scan

optional arguments:
  -h, --help   show this help message and exit
  -f, --fixes  Include fixes in scan
  -t, --tests  Include tests in scan
```

After the command is run, the output will summarize the task IDs for each task for us in later commands.

Example:
```Dix > create_task ../3flatline-demo-files
Filepath provided was a directory, searching for files.
Creating tasks to analyze:
 -- ../3flatline-demo-files/process_image_diss.c
 -- ../3flatline-demo-files/JndiManager.java
 -- ../3flatline-demo-files/imgRead_socket.c
 -- ../3flatline-demo-files/output.md
 -- ../3flatline-demo-files/imgRead
 -- ../3flatline-demo-files/wemo-openwrt-add-header.c
 -- ../3flatline-demo-files/tb_native_host_interface.c
 -- ../3flatline-demo-files/imgRead.rzdb
Estimated file token length: 6258
Created task entry in database for task id: c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef, uploading for analysis.
Successfully uploaded file to server.
Estimated file token length: 2825
Created task entry in database for task id: e76421b6-9108-4ee4-a97c-f85ca6843b4f, uploading for analysis.
Successfully uploaded file to server.
Estimated file token length: 964
Created task entry in database for task id: 84951403-3632-4d9b-a26d-88ba90560645, uploading for analysis.
Successfully uploaded file to server.
File at ../3flatline-demo-files/output.md had unsupported file extension. Skipping.
File at ../3flatline-demo-files/imgRead had unsupported file extension. Skipping.
Estimated file token length: 1042
Created task entry in database for task id: b6b05751-e594-482b-8dd7-ca49ae1df6f9, uploading for analysis.
Successfully uploaded file to server.
Estimated file token length: 6728
Created task entry in database for task id: 311cd276-103a-4294-8b41-c525781f23d2, uploading for analysis.
Successfully uploaded file to server.
File at ../3flatline-demo-files/imgRead.rzdb had unsupported file extension. Skipping.
Task(s) created and file(s) sent to server.  New task ids:
 -- c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef
 -- e76421b6-9108-4ee4-a97c-f85ca6843b4f
 -- 84951403-3632-4d9b-a26d-88ba90560645
 -- b6b05751-e594-482b-8dd7-ca49ae1df6f9
 -- 311cd276-103a-4294-8b41-c525781f23d2
To get the status of a running task use: status -s <uuid>
To get the status of all results of this run: status -s c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef e76421b6-9108-4ee4-a97c-f85ca6843b4f 84951403-3632-4d9b-a26d-88ba90560645 b6b05751-e594-482b-8dd7-ca49ae1df6f9 311cd276-103a-4294-8b41-c525781f23d2
To get full data instead of status, relace 'status' with 'list' in above format
```

## Status

The `status` command will show the status of every analysis task the requesting user has stored in the database. There is an optional flag to search by task id that can be added with `-s`. After the command is run, there will also be output listing every task id you checked the status of. This can be helpful for deleting large numbers of tasks or requesting specific task ids in later commands.

```Usage: status [-h] [-s [SEARCH [...]]]

List status of all code scanning tasks in your account (-s for search by task id)

optional arguments:
  -h, --help            show this help message and exit
  -s, --search [SEARCH [...]]
                        Get status for only specific task ID(s)
```

Example:
```
Dix > status -s c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef e76421b6-9108-4ee4-a97c-f85ca6843b4f 84951403-3632-4d9b-a26d-88ba90560645 b6b05751-e594-482b-8dd7-ca49ae1df6f9 311cd276-103a-4294-8b41-c525781f23d2
Retrieving: c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef
Retrieving: e76421b6-9108-4ee4-a97c-f85ca6843b4f
Retrieving: 84951403-3632-4d9b-a26d-88ba90560645
Retrieving: b6b05751-e594-482b-8dd7-ca49ae1df6f9
Retrieving: 311cd276-103a-4294-8b41-c525781f23d2
Task ID                               Filepath                                Created          Status    
---------------------------------------------------------------------------------------------------------
c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef  ../3flatline-demo-files/process_image_  2023-11-27       COMPLETE  
                                      diss.c                                  16:45:04.381685            
                                                                                                         
e76421b6-9108-4ee4-a97c-f85ca6843b4f  ../3flatline-demo-files/JndiManager.ja  2023-11-27       COMPLETE  
                                      va                                      16:45:07.399727            
                                                                                                         
84951403-3632-4d9b-a26d-88ba90560645  ../3flatline-demo-files/imgRead_socket  2023-11-27       COMPLETE  
                                      .c                                      16:45:07.999710            
                                                                                                         
b6b05751-e594-482b-8dd7-ca49ae1df6f9  ../3flatline-demo-files/wemo-openwrt-a  2023-11-27       COMPLETE  
                                      dd-header.c                             16:45:08.502516            
                                                                                                         
311cd276-103a-4294-8b41-c525781f23d2  ../3flatline-demo-files/tb_native_host  2023-11-27       RUNNING   
                                      _interface.c                            16:45:08.967782            
Task ids from this command for use in other commands: c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef e76421b6-9108-4ee4-a97c-f85ca6843b4f 84951403-3632-4d9b-a26d-88ba90560645 b6b05751-e594-482b-8dd7-ca49ae1df6f9 311cd276-103a-4294-8b41-c525781f23d2
```

## List Task Results

The `list` command will show the results of all tasks currently stored in the database.  There is an optional flag to search by task id that can be added with `-s`.  If you want to download the results, you can do so by adding the `-d` flag after any searched task ids, followed by the output file path.  You can further format the download into markdown using the `-m` flag.

```
Dix > list -h 
Usage: list [-h] [-s [SEARCH [...]]] [-m] [-d DOWNLOAD]

List all code scanning tasks in your account (-s for search by task id)

optional arguments:
  -h, --help            show this help message and exit
  -s, --search [SEARCH [...]]
                        List only specific task ID(s) information
  -m, --markdown        Change cmd2 format to markdown (requires -d, otherwise ignored)
  -d, --download DOWNLOAD
                        Download the results to specific file path
```

Example:

```
Dix > list -s c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef e76421b6-9108-4ee4-a97c-f85ca6843b4f 84951403-3632-4d9b-a26d-88ba90560645 b6b05751-e594-482b-8dd7-ca49ae1df6f9 311cd276-103a-4294-8b41-c525781f23d2 -m -d output.md
Retrieving: c11f6afe-eaf5-4ee1-a9f5-3428b2a92fef
Retrieving: e76421b6-9108-4ee4-a97c-f85ca6843b4f
Retrieving: 84951403-3632-4d9b-a26d-88ba90560645
Retrieving: b6b05751-e594-482b-8dd7-ca49ae1df6f9
Retrieving: 311cd276-103a-4294-8b41-c525781f23d2
Results:
[
... Results ...
]
Converting to markdown.
Converting to markdown.
Converting to markdown.
Converting to markdown.
Converting to markdown.
```

## Delete Task

The `delete` command will delete the results of the task id provided from the database. Note: this is a permanent deletion. We do not archive or maintain results other than the record that is deleted using this command.  This command can work with one or many task ids.

```
Dix > delete -h
Usage: delete [-h] [task_ids [...]]

Delete as task from the database by task id

positional arguments:
  task_ids    Delete task(s) from the database

optional arguments:
  -h, --help  show this help message and exit
```
Example:

```
Dix > delete 37cb34f8-2159-4f55-ba97-122ef0d17434 90c736a7-4b09-40b0-b821-81ccefe26910 979aab87-ba85-4b3f-a49d-6f74d7ad83bd d8bd839b-df9a-4e36-aaa5-eae3e10c6694 dac70b3b-ea9e-41be-9a4a-acd907960902
Deleted task 37cb34f8-2159-4f55-ba97-122ef0d17434
Deleted task 90c736a7-4b09-40b0-b821-81ccefe26910
Deleted task 979aab87-ba85-4b3f-a49d-6f74d7ad83bd
Deleted task d8bd839b-df9a-4e36-aaa5-eae3e10c6694
Deleted task dac70b3b-ea9e-41be-9a4a-acd907960902
```

