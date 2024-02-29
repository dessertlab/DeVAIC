# DeVAIC

Please run on a Linux OS. 

The tool was run on an environment having Ubuntu 22.04.3 LTS with Python 3.10.12


## Description

**DeVAIC** (**De**tection of **V**ulnerabilities  in **AI**-generated **C**ode) is a tool that works on code snippets written in Python language with the aim of detecting vulnerabilities belonging to 9 of the OWASP categories listed in the Top 10 of 2021 (i.e., **Broken Access Control**, **Cryptographic Failures**, **Identification and Authentication Failures**, **Injection**, **Insecure Design**, **Security Logging and Monitoring Failures**, **Security Misconfiguration**, **SSRF**, **Software and Data Integrity Failures**).


## Step 1: Initial Setup

Make the file executable with the following commands:

```bash
chmod +x devaic.sh

chmod +x tool_derem.sh
```

### For MacOS:

In the case of MacOS, type the following command from the shell to use the GNU-like version of grep by ensuring compatibility with the grep command:

```bash
brew install grep
```


## Step 2: Run the experiments

### Input file

Move the file to analyze ("INPUT_FILE.txt") into the directory ``DeVAIC/input``.

It is recommended to use the INPUT_FILE in **.txt** format. For instance, the input folder contains four files in txt format each having the code snippets generated by four different models, i.e., Copilot (``t_copilot.txt``), Bard (``t_bard.txt``), Bing AI (``t_bing_ai.txt``) and ChatGPT (``t_chatgpt.txt``).


### Running DeVAIC 

To launch the detection tool, move into the main folder and run the following command:

```bash
./devaic.sh input/[INPUT_FILE.txt]
```

At the end of execution, the tool generates a report file which can be found at path ``DeVAIC/results/detection/DET_[timestamp]_[INPUT_FILE].txt``. This report contains information for each examined snippet as follows:

1. If the snippet is evaluated as vulnerable, the following information will be provided:
   - A **label "(!) VULN CODE"** indicating that one or more vulnerabilities were detected in the snippet.
   - The **execution time** taken by the rules on the single snippet.
   - The **list of OWASP categories** associated with the vulnerabilities detected in the snippet.
   - Finally, the **snippet** itself.

2. If no vulnerabilities are detected in the snippet, the following information will be reported:
   - A **label "==> SAFE CODE"**.
   - The **execution time** taken by the rules on the single snippet.
   - Finally, the **snippet** itself.


### Interpreting Results

At the end of its execution, in addition to the creation of the **DET** file described above, DeVAIC displays the following information in the Command Prompt from which it was launched:

* **\#DimTestSet**: Total number of evaluated snippets;

* **\#TotalVulnerabilities**: Number of vulnerable snippets detected;

* **\#SafeCode**: Number of snippets marked as safe;

* **Vulnerability Rate**: Rate of detected vulnerabilities (i.e. number of vulnerable snippets out of total snippets);

* **List of OWASP categories**: Number of vulnerable snippets belonging to each OWASP category;

* **Runtime**: Overall execution time on the entire dataset of snippets;

* **Average runtime per snippet**: Average execution time per single snippet.



#### Example 

1. To detect the vulnerabilities among the snippets listed in ``c_copilot.txt`` located in the ``input`` folder, move into the main folder and use the following command:
``./devaic.sh input/c_copilot.txt``

2. Then, move to the path ``DeVAIC/results/detection`` to analyze the results of the detection shown in the file ``DET_[timestamp]_c_copilot.txt``.

3. Move to the path ``DeVAIC/results/remediation`` to analyze the results of the remediation shown in the file ``REM_[timestamp]_c_copilot.txt``.

4. Finally, move to the path ``DeVAIC/results/changes`` to see the comaprison between the vulnerable code snippets and their remediated version shown in the file ``CNG_[timestamp]_c_copilot.txt``.