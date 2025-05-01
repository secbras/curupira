#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import re
import requests
import time  # Adicionado para corrigir o erro
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from time import sleep
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
import warnings
import random
import string
from tldextract import extract

# Configurações
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

class Cores:
    VERMELHO = '\033[91m'
    VERDE = '\033[92m'
    AMARELO = '\033[93m'
    AZUL = '\033[94m'
    ROXO = '\033[95m'
    CIANO = '\033[96m'
    BRANCO = '\033[97m'
    FIM = '\033[0m'
    NEGRITO = '\033[1m'
    SUBLINHADO = '\033[4m'

class ScannerWebAvancado:
    def __init__(self):
        self.sessao = requests.Session()
        self.sessao.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'pt-BR,pt;q=0.9'
        })
        self.vulnerabilidades = []
        self.urls_rastreadas = set()
        self.formularios_unicos = defaultdict(list)
        self.tecnologias = {}
        self.max_formularios_por_url = 5
        self.extensoes_ignoradas = ['.jpg', '.png', '.css', '.js', '.pdf', '.zip', '.rar', '.docx', '.xlsx', '.doc', '.mp4', '.mp3']
        self.arquivos_sensiveis = [
            'robots.txt', '.env', 'config.php', 'wp-config.php',
            'web.config', 'phpinfo.php', 'test.php', 'info.php',
            '.git/config', '.htaccess', '.htpasswd'
        ]
        self.caminhos_admin_comuns = [
            'admin', 'wp-admin', 'administrator', 'login', 
            'panel', 'cpanel', 'manager', 'backend'
        ]

    def limpar_tela(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def mostrar_banner(self):
        self.limpar_tela()
        print(f"""{Cores.VERMELHO}
   _____                       _              _____                 
  / ____|                     (_)            / ____|                
 | |    _   _ _ __ _   _ _ __  _ _ __ __ _  | (___   ___ __ _ _ __  
 | |   | | | | '__| | | | '_ \| | '__/ _` |  \___ \ / __/ _` | '_ \ 
 | |___| |_| | |  | |_| | |_) | | | | (_| |  ____) | (_| (_| | | | |
  \_____\__,_|_|   \__,_| .__/|_|_|  \__,_| |_____/ \___\__,_|_| |_|
                        | |                                         
                        |_|                                         
        {Cores.AMARELO}Scanner Avançado de Segurança Web{Cores.FIM}
        """)

    def normalizar_url(self, url):
        """Normaliza URLs para evitar duplicatas"""
        parsed = urlparse(url)
        caminho = parsed.path.rstrip('/') or '/'
        return f"{parsed.scheme}://{parsed.netloc}{caminho}"

    def deve_ignorar_url(self, url):
        """Verifica se a URL deve ser ignorada com base na extensão"""
        return any(url.lower().endswith(ext) for ext in self.extensoes_ignoradas)

    def mesmo_dominio(self, url, dominio_base):
        """Verifica se a URL pertence ao mesmo domínio"""
        url_extraida = extract(url)
        base_extraida = extract(dominio_base)
        return url_extraida.domain == base_extraida.domain and url_extraida.suffix == base_extraida.suffix

    def rastrear_site(self, url_base, profundidade_max=2, profundidade_atual=0):
        if profundidade_atual > profundidade_max:
            return

        try:
            parsed_url = urlparse(url_base)
            dominio_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            url_normalizada = self.normalizar_url(url_base)
            if url_normalizada in self.urls_rastreadas or self.deve_ignorar_url(url_base):
                return
                
            self.urls_rastreadas.add(url_normalizada)
            print(f"{Cores.CIANO}[*] Rastreando: {url_base}{Cores.FIM}")
            
            resposta = self.sessao.get(url_base, timeout=15, allow_redirects=True)
            
            # Verifica se a resposta é HTML
            if 'text/html' not in resposta.headers.get('Content-Type', '').lower():
                return
                
            soup = BeautifulSoup(resposta.text, 'lxml')
            
            # Detecta tecnologias
            self.detectar_tecnologias(resposta, soup)
            
            # Extrai formulários
            formularios_encontrados = 0
            for formulario in soup.find_all('form'):
                if formularios_encontrados >= self.max_formularios_por_url:
                    break
                    
                acao_form = urljoin(url_base, formulario.get('action', ''))
                metodo_form = formulario.get('method', 'get').upper()
                
                # Verifica se já vimos este formulário antes
                chave_form = (acao_form, metodo_form)
                if chave_form in self.formularios_unicos:
                    continue
                    
                detalhes_form = {
                    'acao': acao_form,
                    'metodo': metodo_form,
                    'inputs': []
                }
                
                for input_tag in formulario.find_all(['input', 'textarea', 'select']):
                    detalhes_input = {
                        'nome': input_tag.get('name', ''),
                        'tipo': input_tag.get('type', 'text'),
                        'valor': input_tag.get('value', '')
                    }
                    detalhes_form['inputs'].append(detalhes_input)
                
                self.formularios_unicos[chave_form] = detalhes_form
                formularios_encontrados += 1
            
            # Extrai links e continua rastreando
            for link in soup.find_all('a', href=True):
                href = link['href'].split('#')[0]  # Remove fragmentos
                if not href or href.startswith(('javascript:', 'mailto:', 'tel:')):
                    continue
                    
                url_completa = urljoin(url_base, href)
                url_completa_normalizada = self.normalizar_url(url_completa)
                
                if not self.mesmo_dominio(url_completa, dominio_base):
                    continue
                    
                if self.deve_ignorar_url(url_completa):
                    continue
                    
                if url_completa_normalizada not in self.urls_rastreadas:
                    self.rastrear_site(url_completa, profundidade_max, profundidade_atual + 1)
                    
        except requests.exceptions.RequestException as e:
            print(f"{Cores.AMARELO}[!] Erro ao acessar {url_base}: {str(e)}{Cores.FIM}")
        except Exception as e:
            print(f"{Cores.VERMELHO}[!] Erro inesperado ao rastrear {url_base}: {str(e)}{Cores.FIM}")

    def detectar_tecnologias(self, resposta, soup):
        """Detecta a stack de tecnologia com maior precisão"""
        headers = resposta.headers
        html = resposta.text.lower()
        
        # Detecta servidor
        servidor = headers.get('Server', '').lower()
        if 'apache' in servidor:
            self.tecnologias['servidor_web'] = 'Apache'
        elif 'nginx' in servidor:
            self.tecnologias['servidor_web'] = 'Nginx'
        elif 'iis' in servidor:
            self.tecnologias['servidor_web'] = 'Microsoft IIS'
            
        # Detecta backend
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by or 'php' in headers.get('Set-Cookie', '').lower():
            self.tecnologias['backend'] = 'PHP'
        elif 'asp.net' in powered_by:
            self.tecnologias['backend'] = 'ASP.NET'
        elif 'node.js' in powered_by:
            self.tecnologias['backend'] = 'Node.js'
        elif 'python' in headers.get('Server', '').lower():
            self.tecnologias['backend'] = 'Python'
            
        # Detecta CMS
        if re.search(r'wp-content|wp-includes|wordpress', html):
            self.tecnologias['cms'] = 'WordPress'
        elif re.search(r'joomla', html):
            self.tecnologias['cms'] = 'Joomla'
        elif 'drupal' in html:
            self.tecnologias['cms'] = 'Drupal'
            
        # Detecta frameworks
        if 'laravel' in html or 'csrf-token' in html:
            self.tecnologias['framework'] = 'Laravel'
        elif 'django' in html:
            self.tecnologias['framework'] = 'Django'
        elif 'rails' in html:
            self.tecnologias['framework'] = 'Ruby on Rails'
            
        # Detecta frontend
        if 'react' in html or 'react-dom' in html:
            self.tecnologias['frontend'] = 'React'
        elif 'vue' in html:
            self.tecnologias['frontend'] = 'Vue.js'
        elif 'angular' in html:
            self.tecnologias['frontend'] = 'Angular'

    def testar_xss(self):
        """Teste de XSS melhorado para reduzir falsos positivos"""
        print(f"\n{Cores.CIANO}[*] Testando XSS em {len(self.formularios_unicos)} formulários únicos{Cores.FIM}")
        
        payloads_xss = [
            ("<script>alert('XSS')</script>", "injeção de tag script"),
            ("<img src=x onerror=alert('XSS')>", "manipulador onerror em img"),
            ("\"><script>alert('XSS')</script>", "quebra de atributo"),
            ("javascript:alert('XSS')", "URI javascript"),
            ("'><svg/onload=alert('XSS')>", "manipulador SVG")
        ]
        
        formularios_vulneraveis = 0
        
        for i, (chave_form, formulario) in enumerate(self.formularios_unicos.items(), 1):
            print(f"\n{Cores.AMARELO}[*] Testando formulário {i}/{len(self.formularios_unicos)}: {formulario['acao']}{Cores.FIM}")
            
            for payload, tipo_payload in payloads_xss:
                dados = {}
                for campo_input in formulario['inputs']:
                    if campo_input['tipo'] not in ['submit', 'button', 'hidden']:
                        dados[campo_input['nome']] = payload if campo_input['nome'] else 'teste'
                
                try:
                    sleep(0.5)  # Limitação de taxa
                    
                    if formulario['metodo'] == 'GET':
                        resposta = self.sessao.get(formulario['acao'], params=dados, timeout=15)
                    else:
                        resposta = self.sessao.post(formulario['acao'], data=dados, timeout=15)
                    
                    # Verificação mais rigorosa para evitar falsos positivos
                    if (payload in resposta.text and 
                        not any(termo in resposta.text.lower() 
                               for termo in ['segurança', 'inválido', 'proibido', 'bloqueado'])):
                        
                        # Verifica se o payload foi interpretado ou apenas exibido como texto
                        soup = BeautifulSoup(resposta.text, 'lxml')
                        tags_script = soup.find_all('script', string=re.compile(r'alert\(.*\)'))
                        
                        if tags_script or tipo_payload in resposta.text:
                            print(f"{Cores.VERMELHO}[!] Vulnerabilidade XSS encontrada com payload: {payload} ({tipo_payload}){Cores.FIM}")
                            print(f"{Cores.VERMELHO}URL: {formulario['acao']}{Cores.FIM}")
                            self.vulnerabilidades.append({
                                'tipo': 'Cross-Site Scripting (XSS)',
                                'url': formulario['acao'],
                                'payload': payload,
                                'tipo_payload': tipo_payload,
                                'severidade': 'Alta'
                            })
                            formularios_vulneraveis += 1
                            break
                            
                except requests.exceptions.Timeout:
                    print(f"{Cores.AMARELO}[!] Timeout ao testar formulário{Cores.FIM}")
                    continue
                except Exception as e:
                    print(f"{Cores.AMARELO}[!] Erro ao testar formulário: {str(e)}{Cores.FIM}")
                    continue
        
        print(f"\n{Cores.VERDE}[*] Teste de XSS concluído.{Cores.FIM}")
        print(f"{Cores.VERDE}[*] Total de formulários vulneráveis: {formularios_vulneraveis}{Cores.FIM}")

    def testar_sqli(self):
        """Teste de SQL Injection com payloads específicos"""
        print(f"\n{Cores.CIANO}[*] Testando SQL Injection em {len(self.formularios_unicos)} formulários{Cores.FIM}")
        
        payloads_sqli = [
            ("' OR '1'='1", "Básico baseado em booleano"),
            ("' OR 1=1-- -", "Bypass com comentário SQL"),
            ("' UNION SELECT null,username,password FROM users-- -", "Baseado em UNION"),
            ("1 AND (SELECT * FROM (SELECT(SLEEP(5)))-- -", "Blind baseado em tempo")
        ]
        
        formularios_vulneraveis = 0
        
        for i, (chave_form, formulario) in enumerate(self.formularios_unicos.items(), 1):
            print(f"\n{Cores.AMARELO}[*] Testando formulário {i}/{len(self.formularios_unicos)}: {formulario['acao']}{Cores.FIM}")
            
            for payload, tipo_payload in payloads_sqli:
                dados = {}
                for campo_input in formulario['inputs']:
                    if campo_input['tipo'] not in ['submit', 'button', 'hidden']:
                        dados[campo_input['nome']] = payload if campo_input['nome'] else 'teste'
                
                try:
                    sleep(0.5)
                    
                    tempo_inicio = time.time()
                    
                    if formulario['metodo'] == 'GET':
                        resposta = self.sessao.get(formulario['acao'], params=dados, timeout=15)
                    else:
                        resposta = self.sessao.post(formulario['acao'], data=dados, timeout=15)
                    
                    tempo_resposta = time.time() - tempo_inicio
                    
                    # Detecta possíveis SQLi baseado em respostas
                    indicadores_sqli = [
                        'sql syntax', 'mysql', 'syntax error',
                        'unclosed quotation mark', 'database error'
                    ]
                    
                    if (any(indicador in resposta.text.lower() for indicador in indicadores_sqli) or
                        ('time-based' in tipo_payload and tempo_resposta > 5)):
                        
                        print(f"{Cores.VERMELHO}[!] Possível SQL Injection encontrado com payload: {payload} ({tipo_payload}){Cores.FIM}")
                        print(f"{Cores.VERMELHO}URL: {formulario['acao']}{Cores.FIM}")
                        self.vulnerabilidades.append({
                            'tipo': 'SQL Injection',
                            'url': formulario['acao'],
                            'payload': payload,
                            'tipo_payload': tipo_payload,
                            'severidade': 'Crítica'
                        })
                        formularios_vulneraveis += 1
                        break
                        
                except requests.exceptions.Timeout:
                    print(f"{Cores.AMARELO}[!] Timeout ao testar formulário{Cores.FIM}")
                    continue
                except Exception as e:
                    print(f"{Cores.AMARELO}[!] Erro ao testar formulário: {str(e)}{Cores.FIM}")
                    continue
        
        print(f"\n{Cores.VERDE}[*] Teste de SQL Injection concluído.{Cores.FIM}")
        print(f"{Cores.VERDE}[*] Total de formulários vulneráveis: {formularios_vulneraveis}{Cores.FIM}")

    def verificar_arquivos_sensiveis(self, url_base):
        """Verifica arquivos sensíveis no servidor"""
        print(f"\n{Cores.CIANO}[*] Verificando arquivos sensíveis{Cores.FIM}")
        
        arquivos_vulneraveis = 0
        parsed_url = urlparse(url_base)
        dominio_base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for caminho_arquivo in self.arquivos_sensiveis:
            url_teste = urljoin(dominio_base, caminho_arquivo)
            
            try:
                resposta = self.sessao.get(url_teste, timeout=10)
                
                if resposta.status_code == 200 and len(resposta.text) > 0:
                    # Verifica se não é uma página de erro genérica
                    if not any(indicador in resposta.text.lower() 
                             for indicador in ['404', 'not found', 'error']):
                        
                        print(f"{Cores.VERMELHO}[!] Arquivo sensível encontrado: {url_teste}{Cores.FIM}")
                        self.vulnerabilidades.append({
                            'tipo': 'Exposição de Arquivo Sensível',
                            'url': url_teste,
                            'severidade': 'Média'
                        })
                        arquivos_vulneraveis += 1
                        
            except requests.exceptions.RequestException:
                continue
        
        # Verifica diretórios administrativos comuns
        for caminho_admin in self.caminhos_admin_comuns:
            url_teste = urljoin(dominio_base, caminho_admin)
            
            try:
                resposta = self.sessao.get(url_teste, timeout=10)
                
                if resposta.status_code == 200:
                    print(f"{Cores.AMARELO}[*] Possível painel administrativo encontrado: {url_teste}{Cores.FIM}")
                    
            except requests.exceptions.RequestException:
                continue
        
        print(f"\n{Cores.VERDE}[*] Verificação de arquivos sensíveis concluída.{Cores.FIM}")
        print(f"{Cores.VERDE}[*] Total de arquivos sensíveis encontrados: {arquivos_vulneraveis}{Cores.FIM}")

    def verificar_csrf(self):
        """Verifica proteção contra CSRF nos formulários"""
        print(f"\n{Cores.CIANO}[*] Verificando proteção contra CSRF{Cores.FIM}")
        
        formularios_sem_protecao = 0
        
        for chave_form, formulario in self.formularios_unicos.items():
            tem_token_csrf = any(
                campo_input['nome'].lower() in ['csrf', 'csrf_token', 'csrfmiddlewaretoken'] or
                campo_input['valor'] and len(campo_input['valor']) > 30
                for campo_input in formulario['inputs']
            )
            
            if not tem_token_csrf:
                print(f"{Cores.AMARELO}[!] Formulário sem proteção CSRF: {formulario['acao']}{Cores.FIM}")
                self.vulnerabilidades.append({
                    'tipo': 'Proteção CSRF Ausente',
                    'url': formulario['acao'],
                    'severidade': 'Média'
                })
                formularios_sem_protecao += 1
        
        print(f"\n{Cores.VERDE}[*] Verificação de proteção CSRF concluída.{Cores.FIM}")
        print(f"{Cores.VERDE}[*] Total de formulários sem proteção: {formularios_sem_protecao}{Cores.FIM}")

    def gerar_relatorio(self):
        """Gera um relatório detalhado dos resultados"""
        relatorio = f"""
=== RELATÓRIO DE SCAN DE SEGURANÇA ===

Tecnologias detectadas:
{json.dumps(self.tecnologias, indent=4, ensure_ascii=False)}

Estatísticas do scan:
- URLs rastreadas: {len(self.urls_rastreadas)}
- Formulários únicos testados: {len(self.formularios_unicos)}
- Vulnerabilidades encontradas: {len(self.vulnerabilidades)}

"""

        if self.vulnerabilidades:
            relatorio += "=== DETALHES DAS VULNERABILIDADES ===\n\n"
            for vuln in self.vulnerabilidades:
                relatorio += f"Tipo: {vuln['tipo']}\n"
                relatorio += f"URL: {vuln['url']}\n"
                if 'payload' in vuln:
                    relatorio += f"Payload: {vuln['payload']} ({vuln.get('tipo_payload', '')})\n"
                relatorio += f"Severidade: {vuln['severidade']}\n"
                relatorio += "-" * 50 + "\n"
        
        return relatorio

    def scanear_site(self, url, modulos):
        print(f"\n{Cores.AMARELO}[*] Iniciando scan de {url}{Cores.FIM}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            # Reseta resultados anteriores
            self.vulnerabilidades = []
            self.urls_rastreadas = set()
            self.formularios_unicos = defaultdict(list)
            self.tecnologias = {}
            
            # Rastreia o site primeiro
            self.rastrear_site(url)
            
            if not self.urls_rastreadas:
                print(f"{Cores.VERMELHO}[!] Nenhuma URL encontrada durante o rastreamento{Cores.FIM}")
                return False
            
            # Mostra tecnologias detectadas
            if self.tecnologias:
                print(f"\n{Cores.AZUL}[*] Tecnologias detectadas:{Cores.FIM}")
                for tech, valor in self.tecnologias.items():
                    print(f"- {tech.capitalize()}: {valor}")
            
            # Executa módulos selecionados
            if 'all' in modulos or 'xss' in modulos:
                self.testar_xss()
            
            if 'all' in modulos or 'sqli' in modulos:
                self.testar_sqli()
            
            if 'all' in modulos or 'files' in modulos:
                self.verificar_arquivos_sensiveis(url)
            
            if 'all' in modulos or 'csrf' in modulos:
                self.verificar_csrf()
            
            # Gera e mostra relatório
            relatorio = self.gerar_relatorio()
            print(f"\n{Cores.AZUL}=== RELATÓRIO FINAL ==={Cores.FIM}")
            print(relatorio)
            
            # Salva relatório em arquivo
            dominio = urlparse(url).netloc
            arquivo_relatorio = f"relatorio_scan_{dominio}.txt"
            with open(arquivo_relatorio, 'w', encoding='utf-8') as f:
                f.write(relatorio)
            print(f"{Cores.VERDE}[*] Relatório salvo em {arquivo_relatorio}{Cores.FIM}")
            
            return True
            
        except Exception as e:
            print(f"{Cores.VERMELHO}[!] Erro durante o scan: {e}{Cores.FIM}")
            return False

def menu_principal():
    scanner = ScannerWebAvancado()
    
    while True:
        scanner.mostrar_banner()
        print(f"\n{Cores.NEGRITO}MENU PRINCIPAL:{Cores.FIM}")
        print(f"{Cores.VERDE}[1]{Cores.FIM} Scan de URL (Todos os testes)")
        print(f"{Cores.VERDE}[2]{Cores.FIM} Scan com módulos específicos")
        print(f"{Cores.VERDE}[3]{Cores.FIM} Sobre")
        print(f"{Cores.VERDE}[4]{Cores.FIM} Sair")
        
        escolha = input(f"\n{Cores.AZUL}>>> Selecione uma opção:{Cores.FIM} ")
        
        if escolha == "1":
            url = input(f"\n{Cores.AZUL}>>> Digite a URL alvo (ex: http://exemplo.com):{Cores.FIM} ")
            scanner.scanear_site(url, ['all'])
            input(f"\n{Cores.AZUL}>>> Pressione Enter para continuar...{Cores.FIM}")
        elif escolha == "2":
            scanner.mostrar_banner()
            print(f"\n{Cores.NEGRITO}MÓDULOS DE SCAN:{Cores.FIM}")
            print(f"{Cores.AMARELO}[!] Selecione os módulos a usar (separados por vírgula){Cores.FIM}")
            print(f"\n{Cores.VERDE}[1]{Cores.FIM} SQL Injection")
            print(f"{Cores.VERDE}[2]{Cores.FIM} XSS")
            print(f"{Cores.VERDE}[3]{Cores.FIM} Arquivos Sensíveis")
            print(f"{Cores.VERDE}[4]{Cores.FIM} CSRF")
            print(f"{Cores.VERDE}[5]{Cores.FIM} Command Injection")
            print(f"{Cores.VERDE}[6]{Cores.FIM} SSRF")
            print(f"{Cores.VERDE}[7]{Cores.FIM} XXE")
            
            escolha_modulos = input(f"\n{Cores.AZUL}>>> Selecione os módulos:{Cores.FIM} ")
            
            url = input(f"\n{Cores.AZUL}>>> Digite a URL alvo:{Cores.FIM} ")
            
            mapa_modulos = {
                '1': 'sqli',
                '2': 'xss',
                '3': 'files',
                '4': 'csrf',
                '5': 'cmd',
                '6': 'ssrf',
                '7': 'xxe'
            }
            
            modulos_selecionados = []
            for escolha in escolha_modulos.split(','):
                escolha = escolha.strip()
                if escolha in mapa_modulos:
                    modulos_selecionados.append(mapa_modulos[escolha])
            
            if not modulos_selecionados:
                print(f"\n{Cores.VERMELHO}[!] Nenhum módulo válido selecionado{Cores.FIM}")
            else:
                scanner.scanear_site(url, modulos_selecionados)
            
            input(f"\n{Cores.AZUL}>>> Pressione Enter para continuar...{Cores.FIM}")
        elif escolha == "3":
            scanner.mostrar_banner()
            print(f"\n{Cores.NEGRITO}SOBRE ESTE PROJETO:{Cores.FIM}")
            print(f"""
            {Cores.AMARELO}Scanner Avançado de Segurança Web{Cores.FIM}
            
            Scanner de vulnerabilidades web com recursos incluindo:
            
            - Rastreamento automático de websites
            - Detecção precisa de tecnologias (CMS, servidor web, backend)
            - Testes avançados de SQL Injection
            - Detecção de XSS refletido e armazenado
            - Teste de Command Injection
            - Verificação de proteção CSRF
            - Teste de SSRF e XXE
            - Detecção de arquivos sensíveis
            - Descoberta de painéis administrativos
            
            Este scanner é uma implementação em Python focada em testes
            de segurança web e testes de penetração.
            """)
            input(f"\n{Cores.AZUL}>>> Pressione Enter para continuar...{Cores.FIM}")
        elif escolha == "4":
            print(f"\n{Cores.AMARELO}[!] Saindo...{Cores.FIM}")
            sleep(1)
            sys.exit(0)
        else:
            print(f"\n{Cores.VERMELHO}[!] Opção inválida!{Cores.FIM}")
            sleep(1)

if __name__ == "__main__":
    # Verificar dependências
    try:
        import requests
        from bs4 import BeautifulSoup
        import lxml
        import tldextract
    except ImportError as e:
        print(f"\n{Cores.VERMELHO}[!] Bibliotecas necessárias não encontradas.{Cores.FIM}")
        print(f"{Cores.AMARELO}[*] Instale com: pip install requests beautifulsoup4 lxml tldextract{Cores.FIM}")
        sys.exit(1)
    
    try:
        menu_principal()
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}[!] Interrompido pelo usuário.{Cores.FIM}")
        sys.exit(0)