# Sentinel-AI: Automated Code Auditor 🤖🛡️

> **Next-Gen SAST tool that detects vulnerabilities using AST analysis and suggests automated fixes using GenAI.**

![Python](https://img.shields.io/badge/Python-AST-blue)
![AI](https://img.shields.io/badge/AI-GenAI_Integration-green)
![Security](https://img.shields.io/badge/Focus-DevSecOps-red)

---

## 📖 Overview
**Sentinel-AI** goes beyond traditional SAST tools.  
It not only detects common vulnerabilities such as **SQL Injection**, **Hardcoded Secrets**, and insecure patterns by analyzing the **Abstract Syntax Tree (AST)**, but also generates **secure code patches** automatically using GenAI.

---

## ⚙️ Installation

```bash
git clone https://github.com/osmankaankars/Sentinel-AI.git
cd Sentinel-AI
pip install -r requirements.txt
```

---

## 🚀 Usage

Run Sentinel-AI against a target Python file:

```bash
python sentinel.py vulnerable_app.py
```

By default, it runs in **Mock Mode**, simulating AI-generated patches without calling any external APIs.

To enable **live LLM-based patching**, use:

```bash
python sentinel.py vulnerable_app.py --mode openai --key YOUR_KEY
```

---

## 👨‍💻 Author
**Osman Kaan Kars**  
Cybersecurity Engineer | SAP Security Specialist  

**LinkedIn:** https://linkedin.com/in/osmankaankars  
**GitHub:** https://github.com/osmankaankars
