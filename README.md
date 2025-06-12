This repository contains **two versions** of the code related to the paper **DeVAIC: A Tool for Security Assessment of AI-generated Code** accepted for publication in **Information and Software Technology** (**IST**) journal.

## Description

**DeVAIC** (**De**tection of **V**ulnerabilities  in **AI**-generated **C**ode) is a fast static analysis tool for detecting vulnerabilities in code written in Python language.


## 📁 Repository Structure

- **`version_1.0/`**: Original version of the detection tool. It features:
  - A basic code structure
  - Vulnerability detection applied **only to single-line code snippets**
- **`version_2.0/`**: Updated and improved version of the tool.  This version includes:
  - A reorganized code structure for better modularity and maintainability
  - New and extended detection rules
  - Broader coverage of vulnerability types
  - Ability to analyze complete **Python source files (`.py`)**, not just single lines

## 🔍 Purpose

The tool is designed to support research and development in the field of vulnerability detection, particularly for Python code. It can be used to analyze codebases and identify security issues based on predefined vulnerability patterns.

## 🚀 Getting Started

To run the tool, navigate to the desired version directory and follow the instructions in its respective `README.md` files.



## 🧩 Detection Rules

The rules cover a range of vulnerabilities, including but not limited to:

- Hardcoded credentials
- Insecure deserialization
- Command injection
- Improper input validation
- And more (see `version_2.0/ruleset/` for the full list)


## 📌 Notes

- Version 2.0 is recommended for most use cases due to its broader coverage and improved architecture.
- Version 1.0 is preserved for historical and comparison purposes.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

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