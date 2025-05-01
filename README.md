<img src="https://github.com/secbras/curupira/blob/main/curupira.png?raw=true" alt="Alabin v1.0">

# 🧠 Curupira – Scanner Avançado de Segurança Web

Curupira é uma ferramenta de código aberto desenvolvida em Python 3 que realiza varreduras automatizadas em aplicações web para identificar vulnerabilidades comuns, como XSS, SQL Injection, Command Injection, SSRF, XXE, além de detectar arquivos sensíveis e diretórios administrativos expostos.

---

## 🎯 Funcionalidades

- Rastreamento recursivo de sites com controle de profundidade.
- Identificação de formulários únicos por URL.
- Execução de testes com payloads para:
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - Command Injection
  - SSRF (Server-Side Request Forgery)
  - XXE (XML External Entity)
- Detecção de arquivos sensíveis (e.g., `.env`, `wp-config.php`, `.git/config`).
- Verificação de caminhos administrativos comuns (e.g., `/admin`, `/login`).
- Identificação de tecnologias utilizadas no site (e.g., frameworks, CMS).
- Interface de linha de comando com saída colorida para melhor visualização.

---

## 🚀 Requisitos

- Python 3.6 ou superior

### 📦 Dependências Python

- `requests`
- `beautifulsoup4`
- `tldextract`
- `lxml`

Você pode instalá-las com:

```bash
pip install -r requirements.txt
```

Ou manualmente:

```bash
pip install requests beautifulsoup4 tldextract lxml
```

---

## ⚙️ Instalação

```bash
git clone https://github.com/secbras/curupira.git
cd curupira
pip install -r requirements.txt
```

---

## 🛠️ Uso

Execute o scanner com o comando:

```bash
python curupira.py
```

O script solicitará a URL a ser analisada e iniciará a varredura automaticamente, mostrando os resultados diretamente no terminal.

---

## ⚠️ Aviso Legal

> Esta ferramenta é fornecida exclusivamente para fins educacionais e testes de segurança em ambientes autorizados.  
> **O uso em sistemas sem permissão explícita é ilegal.**  
> Os desenvolvedores **não se responsabilizam** por qualquer uso indevido.

---

## 📄 Licença

Este projeto está licenciado sob a [Licença MIT](LICENSE).

---

