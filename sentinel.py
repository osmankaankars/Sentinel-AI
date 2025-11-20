import ast
import os
import argparse
import requests
from colorama import Fore, Style, init
from diff_match_patch import diff_match_patch

# Renkleri başlat
init(autoreset=True)

class Vulnerability:
    def __init__(self, lineno, vuln_type, code_snippet, description):
        self.lineno = lineno
        self.vuln_type = vuln_type
        self.code_snippet = code_snippet
        self.description = description

class CodeAnalyzer(ast.NodeVisitor):
    """
    Static Analysis Security Testing (SAST) engine using Abstract Syntax Tree.
    """
    def __init__(self, source_code):
        self.source_code = source_code.splitlines()
        self.vulnerabilities = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            # Detect: os.system()
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'system':
                self.add_vuln(node, "Command Injection", "Avoid os.system(). Use subprocess.run() with shell=False.")
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(secret in var_name for secret in ['key', 'secret', 'password', 'token']):
                    if isinstance(node.value, ast.Constant): 
                        self.add_vuln(node, "Hardcoded Secret", "Detected potential secret. Use Environment Variables.")
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        # Demo purpose detection for SQLi in f-strings
        code_segment = self.source_code[node.lineno - 1]
        if "SELECT" in code_segment.upper() or "UPDATE" in code_segment.upper():
             self.add_vuln(node, "SQL Injection", "Possible SQL Injection via f-string. Use parameterized queries (?)")
        self.generic_visit(node)

    def add_vuln(self, node, v_type, desc):
        snippet = self.source_code[node.lineno - 1].strip()
        self.vulnerabilities.append(Vulnerability(node.lineno, v_type, snippet, desc))

class AIPatcher:
    def __init__(self, mode="mock", api_key=None):
        self.mode = mode
        self.api_key = api_key

    def get_fix(self, vuln):
        if self.mode == "mock":
            return self._mock_fix(vuln)
        elif self.mode == "openai":
            return self._openai_fix(vuln)

    def _mock_fix(self, vuln):
        if vuln.vuln_type == "SQL Injection":
            return 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        elif vuln.vuln_type == "Hardcoded Secret":
            return 'aws_key = os.getenv("AWS_KEY")'
        elif vuln.vuln_type == "Command Injection":
            return 'subprocess.run(cmd, shell=False)'
        return "# Fix generation failed"

    def _openai_fix(self, vuln):
        if not self.api_key:
            return "[Error] No API Key"
        prompt = f"Fix this python security vulnerability ({vuln.vuln_type}) in one line:\n{vuln.code_snippet}\n\nProvide ONLY the code."
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        data = {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0
        }
        try:
            response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data)
            return response.json()['choices'][0]['message']['content'].strip()
        except Exception as e:
            return f"# API Error: {str(e)}"

def visualize_diff(original, fixed):
    """
    Uses Google's diff-match-patch to show colorful differences.
    """
    dmp = diff_match_patch()
    # Compute diff
    diffs = dmp.diff_main(original, fixed)
    dmp.diff_cleanupSemantic(diffs)
    
    print(Fore.CYAN + "    [Patch Preview]: ", end="")
    
    for (op, data) in diffs:
        if op == -1: # DELETE (Red & Strikethrough effect logic)
            print(Fore.RED + f"[-{data}-]", end="")
        elif op == 1: # INSERT (Green)
            print(Fore.GREEN + f"{{+{data}+}}", end="")
        else: # EQUAL (White)
            print(Fore.WHITE + data, end="")
    print() # New line

def main():
    parser = argparse.ArgumentParser(description="Sentinel-AI: Automated Code Auditor")
    parser.add_argument("file", help="Python file to scan")
    parser.add_argument("--mode", choices=["mock", "openai"], default="mock", help="AI Mode")
    parser.add_argument("--key", help="OpenAI API Key", default=None)
    
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(Fore.RED + f"[-] File {args.file} not found.")
        return

    print(Fore.CYAN + Style.BRIGHT + f"[*] Sentinel-AI scanning: {args.file}")
    print(Fore.CYAN + f"[*] Engine: AST Analysis + {args.mode.upper()} Patcher")
    
    with open(args.file, "r") as f:
        source = f.read()

    analyzer = CodeAnalyzer(source)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        print(Fore.RED + "[-] Syntax Error in source file. Cannot parse.")
        return
        
    analyzer.visit(tree)

    if not analyzer.vulnerabilities:
        print(Fore.GREEN + "[+] Code looks clean!")
        return

    print(Fore.YELLOW + f"\n[*] Found {len(analyzer.vulnerabilities)} security issues.\n")
    
    patcher = AIPatcher(mode=args.mode, api_key=args.key)

    for i, vuln in enumerate(analyzer.vulnerabilities, 1):
        print(Fore.MAGENTA + "="*60)
        print(Fore.RED + Style.BRIGHT + f"ISSUE #{i}: {vuln.vuln_type}")
        print(Fore.WHITE + f"Location: Line {vuln.lineno}")
        print(Fore.WHITE + f"Description: {vuln.description}")
        print(Fore.MAGENTA + "-"*60)
        
        print(Fore.YELLOW + "    [Original Code]: " + Fore.WHITE + vuln.code_snippet)
        
        # Get fix
        fixed_code = patcher.get_fix(vuln)
        
        # Show Diff
        visualize_diff(vuln.code_snippet, fixed_code)
        print(Fore.MAGENTA + "="*60 + "\n")

if __name__ == "__main__":
    main()
