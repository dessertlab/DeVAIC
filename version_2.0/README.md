# DeVAIC 2.0

## **🚧 Prerequisites:** 
> - Please run on a Linux OS or macOS. For Windows users, you can utilize the [Windows Subsystem for Linux](https://learn.microsoft.com/it-it/windows/wsl/install) (WSL); in this case, please ensure to have the WSL installed before proceeding.
> - Please ensure that Python 3.8 (or later versions) is installed. For Windows users, ensure to have Python installed in WSL.

> #### **🚨 In case you have problem of /bin/bash: bad interpreter:**
> In the `utils` folder, launch this script to ensure that the `.sh` files are in the correct format:
> ```python
>  python convert_to_LF.py
>  ```


## 🛠Setup

### For Linux OS 🐧 or Windows Users 🪟(WSL):

#### (1) Install `jq`

Please install **jq** using the following commands:

> **⚠️ Disclaimer:** If you are a Windows user, you need to install jq in WSL.

```bash
sudo apt-get update

sudo apt-get install jq
```


#### (2) Install Basic Calculator
Please install **bc** using these commands:
```bash
sudo apt-get update

sudo apt install bc
```


#### (3) Make the file executable
Move to the `launch_tool` folder and type this command:
```bash
chmod u+x *.sh
```


## 🚀 Run the experiments

### Input file

Move the file to analyze (e.g., YOUR_INPUT_FILE.txt or YOUR_SCRIPT.py) into the directory ``version_2.0/input``.


### 🎯Running DeVAIC 

(1) If you want to evaulate a `.txt` file containing code samples written in **single line** format, launch this command in the **main** folder:
```bash
./devaic.sh ./input/[YOUR_INPUT_FILE].txt . --multi
```


(2) If you want to evaulate a `.py` file, launch this command in the **main** folder:
```bash
./devaic.sh ./input/[YOUR_SCRIPT].py .
```


> #### **🚨 In case you have problem of /bin/bash: bad interpreter:**
> In the `utils` folder, launch this script to ensure that the `.sh` files are in the correct format:
> ```python
>  python convert_to_LF.py
>  ```


At the end of execution, the tool generates a report file which can be found at path ``version_2.0/results/[timestamp]_[YOUR_INPUT_FILE].json``. 


## 💻 Practical Usage Example 

(1) If you want to evaulate a `.txt` file containing code samples written in **single line** format, launch this command in the **main** folder:
```bash
./devaic.sh ./input/test_multi.txt . --multi
```


(2) If you want to evaulate a `.py` file, launch this command in the **main** folder:
```bash
./devaic.sh ./input/test_source.py .
```

2. Then, move to the path ``version_1.0/results/`` to analyze the results of the detection shown in the file ``[timestamp]_test_multi.json`` and/or ``[timestamp]_test_source.json``.


## Citation

If you use DeVAIC in academic context, please cite it as follows:

```bibtex
@article{COTRONEO2025107572,
title = {DeVAIC: A tool for security assessment of AI-generated code},
journal = {Information and Software Technology},
volume = {177},
pages = {107572},
year = {2025},
issn = {0950-5849},
doi = {https://doi.org/10.1016/j.infsof.2024.107572},
url = {https://www.sciencedirect.com/science/article/pii/S0950584924001770},
author = {Domenico Cotroneo and Roberta {De Luca} and Pietro Liguori},
keywords = {Static code analysis, Vulnerability detection, AI-code generators, Python}
}
