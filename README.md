# DRAIC


## Description

**DRAIC** (**D**etection and **R**emediation tool for **AI**-generated **C**ode) is a tool that works on snippets code written in Python language with the aim of detecting three vulnerability categories: **T**aint **P**ropagation (**TP**), **K**nown **U**nsafe **F**unctions (**KUF**) and **C**onfiguration **P**roblems (**CP**). 

With **TP** we mean the pattern in which there is a tainted variable containing the output of a certain function (*source*). If this variable is then used as an input parameter for a method (*sink*) without being properly validated, then we are faced with a TP scenario. Instead, **KUF** and **CP** indicate deprecated functions or protocols.


## Setup

Make the file executable with the following command:

``chmod +x draic.sh``

``chmod +x tool_derem.sh``



## On macOS, to use the GNU-like version of grep do the following:

To ensure compatibility with the grep command, type the following command from the shell:

``brew install grep``



## Step 1 : Input file

Move the file to analyze (INPUT_FILE) into the directory ``DRAIC/input``.

You can use INPUT_FILE with two different extensions, which are ``.txt`` and ``.json``. If you use ``.json``, make sure the code to be analyzed is indicated by the key ``"code":`` and is between quotation marks [``""``] as the example below:

```json
[
    {
    "text":"The function ping() is called when the URL <url> ping is requested to store URL as a variable \"url\" to return",
    "code":"def ping(): \n  url = request.args.get('url') \n os.system(\"ping -c 1 \" + url) \n  return redirect(url)"
    },
    {
    "text":"Define a function that return a random session ID",
    "code":"def getSessionID():  return random.randint(0,0xFFFFFFFF)"
    }
]
```

The presence of other possible keys (such as ``"text":`` in the example) will be ignored.


## Step 2 : Running DRAIC 

To launch the detection & remediation tool, move into the main folder and run the following command:
``./draic.sh input/[INPUT_FILE]``

At the end of the execution, two files will be generated: 

1. ``DRAIC/results/detection/DET_[timestamp]_[INPUT_FILE].txt``, containing the results of detection;

2. ``DRAIC/results/remediation/REM_[timestamp]_[INPUT_FILE].txt``, containing the results of remediation.


## Step 2 : Interpreting Results

At the end of its execution, in addition to the creation of the **DET** and **REM** files indicated above, DRAIC displays the following information in the Command Prompt from which it was launched:

* \#DimTestSet: Total number of evaluated snippets;

* \#SafeCode: Number of snippets marked as safe;

* \#TotalVuln: Number of vulnerable snippets detected;

* Vulnerability Rate: Rate of detected vulnerabilities (i.e. number of vulnerable snippets out of total snippets);

* \#TP, \#KUF, \#CP: Number of snippets in which TP, KUF and CP vulnerabilities were detected;

* \#TP\_KUF, \#TP\_CP, \#KUF\_CP, \#TP\_KUF\_CP: Number of snippets in which multiple types of vulnerabilities have been detected in all their possible combinations, that is those in which there is both TP and KUF (TP\_KUF), or both TP and CP (TP\_CP), or all other remaining combinations.