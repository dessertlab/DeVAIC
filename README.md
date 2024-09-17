# DeVAIC: A Tool for Security Assessment of AI-generated Code 

This repository contains the code related to the paper "DeVAIC: A Tool for Security Assessment of AI-generated Code" accepted for publication in the **Information and Software Technology (IST)** journal.


## Description

> Please run on a Linux OS. 
The tool was run on an environment having Ubuntu 22.04.3 LTS with Python 3.10.12

**DeVAIC** (**De**tection of **V**ulnerabilities  in **AI**-generated **C**ode) is a fast static analysis tool for detecting vulnerabilities in code written in Python language. It can work even on code snippets, i.e. incomplete code due to the lack of initial import statements, single function definition, etc. It detects vulnerabilities belonging to the OWASP categories listed in the Top 10 of 2021 (i.e., **Broken Access Control**, **Cryptographic Failures**, **Injection**, **Insecure Design**, **Security Misconfiguration**, **Vulnerable and Outdated Components**, **Identification and Authentication Failures**, **Software and Data Integrity Failures**, **Security Logging and Monitoring Failures**, and **SSRF**).


## 🛠️ Step 1: Initial Setup

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


## 🚀 Step 2: Run the experiments

### Input file

Move the file to analyze (e.g., YOUR_INPUT_FILE.txt) into the directory ``DeVAIC/input``.



#### ⚠️ Disclaimer

> **WARNING:** Each **code snippet** in the input file must be **written line by line**. It is recommended to use the YOUR_INPUT_FILE in **.txt** format. 

 

For instance, the input folder contains four files in txt format each having the code snippets generated by four different models, i.e., GitHub Copilot (``github_copilot.txt``), Google Gemini (``google_gemini.txt``), Microsoft Copilot (``microsoft_copilot.txt``) and OpenAI ChatGPT (``openai_chatgpt.txt``).


### Running DeVAIC 

To launch the detection tool, move into the main folder and run the following command:

```bash
./devaic.sh input/[YOUR_INPUT_FILE.txt]
```

At the end of execution, the tool generates a report file which can be found at path ``DeVAIC/results/detection/DET_[timestamp]_[YOUR_INPUT_FILE].txt``. This report contains information for each examined snippet as follows:

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


| Label on prompt             | Meaning                                                        |
|-----------------------------|----------------------------------------------------------------|
| \#DimTestSet                | Total number of evaluated snippets                             |
| \#TotalVulnerabilities      | Number of vulnerable snippets detected                         |
| \#SafeCode                  | Number of snippets marked as safe                              |
| Vulnerability Rate          | Rate of detected vulnerabilities (i.e. number of vulnerable snippets out of total snippets) |
| List of OWASP categories    | Number of vulnerable snippets belonging to each OWASP category |
| Runtime                     | Overall execution time on the entire dataset of snippets       |
| Average runtime per snippet | Average execution time per single snippet                      |


## 💻 Practical Usage Example 

1. To detect the vulnerabilities among the snippets listed in ``github_copilot.txt`` located in the ``input`` folder, move into the main folder and use the following command:
```bash
./devaic.sh input/github_copilot.txt
```

2. Then, move to the path ``DeVAIC/results/detection`` to analyze the results of the detection shown in the file ``DET_[timestamp]_github_copilot.txt``.


## Citation

If you use DeVAIC in academic context, please cite it as follows:

```bibtex
@article{COTRONEO2024107572,
title = {DeVAIC: A tool for security assessment of AI-generated code},
journal = {Information and Software Technology},
pages = {107572},
year = {2024},
issn = {0950-5849},
doi = {https://doi.org/10.1016/j.infsof.2024.107572},
url = {https://www.sciencedirect.com/science/article/pii/S0950584924001770},
author = {Domenico Cotroneo and Roberta {De Luca} and Pietro Liguori},
keywords = {Static code analysis, Vulnerability detection, AI-code generators, Python}
}

