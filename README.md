# DRAIC

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


## Step 2 : Running Detool 

To launch the detection & remediation tool, move into the main folder and run the following command:
``./draic.sh input/[INPUT_FILE]``

At the end of the execution, two files will be generated: 

1 - ``DRAIC/results/detection/DET_[timestamp]_[INPUT_FILE].txt``, containing the results of detection;

2 - ``DRAIC/results/remediation/REM_[timestamp]_[INPUT_FILE].txt``, containing the results of remediation.

