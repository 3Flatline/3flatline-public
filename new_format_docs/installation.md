# Installation

Access to the 3Flatline Dixie platform is accomplished by using a Command Line Interface (CLI).  This CLI has very few requirements, only requiring the following environment and packages:

Python 3.10+
Python packages (also contained in the accompanying `requirements.txt` file):
```
boto3
botocore
cmd2
pyfiglet
requests
tiktoken
```

The following document will walk you through installation of the CLI.

## Step-By-Step
Note: These instructions are for MacOS or Linux.  For Windows, we recommend installing the Windows Subsystem for Linux (WSL).

1) To start, ensure you have Python 3.10+ installed on the desired machine.
2) (Optional) Create a Python virtual environment to install the dependencies and avoid conflict with other installed packages.
```
Create the virtual environment and activate it:

python -m venv /path/to/new/virtual/environment
source /path/to/new/virtual/environment/bin/activate
```
3) Download/install the CLI. It is available as a direct download or PyPI repo depending on your choice.

- Github Download: https://github.com/3Flatline/3flatline-public
Download the source file and decompress it using your desired utility.  Next, install the requirements.txt file using the following command:
`pip install -r requirements.txt`
When this completes, you can run the CLI using the `python` or `python3` command and then providing the path to the CLI location:
`python ./3flatline-cli.py`

- PyPI Repo: https://pypi.org/project/three-flatline-cli/
Run:
`pip install three-flatline-cli`
This will download all the requirements.  Once complete, the CLI can be run using the `3flatline` command:

4) Don't forget to authenticate, and happy hunting!
