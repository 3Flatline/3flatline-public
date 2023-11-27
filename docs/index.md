# Platform Overview

## What does 3Flatline do?

3Flatline Dixie platform is a static code analyzing platform that works on a number of different languages: C/C++. ObjC, Golang, Java, Python, Ruby, JavaScript, PHP, and decompiled pseudo-C. It uses a number of different methods to scan your submitted code and find potential vulnerabilities.

The best way to interface with the Dixie platform is to use the Command Line Interface (CLI).  While there is a web application that allows submission of tasks, the CLI is the intended interface and will allow the most capability.

## How does it work?

The basic process of the Dixie platform is to take your files and analyze them for vulnerabilities. While the platform has various deployment models (public SaaS, private infrastructure, stand-alone machine) they work generally the same way:

- Create an analysis task
- Upload code to the server
- Analyze your code
- Delete source materials

## Privacy
Your source files are only on the servers long enough to be scanned. You retain all rights to your code and to the results: the last thing we want is a database full of proprietary code and potential vulnerabilities contained in it.  To that end, we implement a number of automatic processes:

- All source files are deleted after analysis is complete.
- None of our models are retrained using customer source code or analysis results.
- All analysis results not deleted manually by the user are deleted after 7 days.
- Any processes or external systems used also do not train on our customers' data (for example, any LLM or other models)
- The billing system records cost of analysis, user requesting an analysis, and a timestamp of the analysis for delayed billing models, but does not record file name or folder structure. (Custom billing models only)
- Our team seeks out the most private hosting of LLMs and other analysis components, such as private Azure endpoints or self-hosted containers running on cloud infrastructure to reduce third party exposure to your data. A complete list of third-party exposure to your data is available on request, as well as custom requests for limiting exposure.

### Take away: No human other than you ever looks at your code, and your code is not retained by us or used for retraining.  For those wanting additional privacy we can provide a completely self-contained offline machine (no external services or LLMs) that runs the same analysis as the public SaaS.

## Vulnerable bugs
While 3Flatline finds bugs, it doesn't tell you if they are vulnerable. Determining the reachability of the bug is on our roadmap.

## File Size Limit
Currently, the size of the file to analyze is 18k tokens. What does that mean in english? If a file returns as too big to analyze, break it up into the largest file possible that still is under the token limit. Be sure not to chunk the file in the middle of a function. Doing this automatically is on the roadmap.

## Additional Limitations

Most LLM AI platforms are limited by the number of tokens they can process. As a result, the platform is limited by the amount of context it can process. What does this mean to you? 3Flatine doesn't produce high quality results for bug classes that require a lot of context.

For example: 
- 3Flatline doesn't understand runtime environments. Sending Rust source code can result in a number of false positives, because 3Flatline doesn't understand the memory protections of the Rust runtime. 
- The platform doesn't understand function or class definitions well. Header files and any file that serves the purpose of an interface in object oriented programing doesn't produce good results.
- It also doesn't understand the difference between a class definition and a class implementation. We still recommend having 3Flatline analyze those files. 3Flatline can identify a poorly allocated memory segment in a struct.
- In general, Dixie doesn't do well with highly abstracted code. We recommend running at least the preprocessor against the source code to remove some abstraction. 

3Flatline uses a generative AI LLM and as a result may have false positives. We have reduced those greatly (less than 1 percent), but it can *still* happen.

### C-Based Languages
The platform excels at analysis of any C based language. The model used for these languages is automatically detected based on the file extension.  There is no special handling needed by the user to get the best analysis.

### Decompiled C/Go/Rust
To have Dixie analyze decompiled C, be sure to remove the data section and any trampoline functions. For C like languages(golang, Rust), the best results are from running 3Flatline against the compiled code and not the source. 

### Other Languages
The platform is also effective when used on web application source code (php, ruby etc).  The model used for these languages is automatically detected based on the file extension.  There is no special handling needed by the user to get the best analysis.
