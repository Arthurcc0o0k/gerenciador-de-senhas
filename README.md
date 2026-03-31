# 🔐 Gerenciador de Senhas - Empresa

Um aplicativo seguro e completo para gerenciar senhas corporativas com criptografia de ponta a ponta.

## ✨ Features

- 🔒 **Criptografia Fernet** - Senhas totalmente seguras com PBKDF2-HMAC-SHA256
- 👤 **Senha Mestra** - Acesso protegido a todas as senhas
- 📋 **Copiar para Clipboard** - Copia senhas com limpeza automática após 30s
- 🔐 **Gerar Senhas** - Senhas aleatórias fortes (até 128 caracteres)
- 💾 **Exportar/Importar** - Backup e restauração em JSON
- 🔑 **Mudar Senha Mestra** - Altere sua senha principal quando necessário
- 🔍 **Buscar/Filtrar** - Encontre senhas rapidamente
- 🎨 **Interface Gráfica** - UI intuitiva com Tkinter

## 📋 Requisitos

- Python 3.8+
- pip

## 🚀 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/gerenciador-de-senhas.git
cd gerenciador-de-senhas
```

2. Crie um ambiente virtual:
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# ou
source .venv/bin/activate  # Linux/Mac
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

## 💻 Como Usar

Execute o programa:
```bash
python gerenciador.py
```

### Primeira Execução
1. Crie uma **senha mestra** (não esqueça!)
2. Faça login com essa senha
3. Comece a gerenciar suas senhas

### Operações Disponíveis
- **➕ Adicionar** - Nova entrada de senha
- **✏️ Editar** - Modificar entrada existente
- **❌ Remover** - Deletar entrada
- **👁️ Ver senha** - Visualizar senha descriptografada
- **📋 Copiar** - Copiar para clipboard
- **🔄 Atualizar** - Recarregar lista
- **🔐 Gerar senha** - Criar nova senha aleatória
- **💾 Exportar** - Salvar backup (JSON)
- **📂 Importar** - Restaurar de backup
- **🔑 Mudar senha mestra** - Alterar senha principal
- **🚪 Sair** - Fazer logout

## 🔒 Segurança

⚠️ **Avisos importantes:**
- Nunca compartilhe sua senha mestra
- O arquivo `key.key` contém a chave derivada (arquivo sensível)
- Mantenha backups seguros
- Use senhas fortes (recomendado 16+ caracteres)

## 📁 Estrutura

```
gerenciador-de-senhas/
├── gerenciador.py          # Código principal
├── requirements.txt        # Dependências
├── .gitignore             # Git ignore
├── README.md              # Este arquivo
└── .venv/                 # Ambiente virtual (ignorado)
```

## 📦 Dependências

- `cryptography` - Criptografia segura
- `pyperclip` - Acesso ao clipboard

## 📄 Licença

Este projeto é fornecido "como está" para fins educacionais.

## 👨‍💻 Contribuições

Sinta-se livre para fazer fork e submeter pull requests com melhorias!

## ⚠️ Aviso de Disclaimer

Este é um projeto educacional. Use por sua conta e risco em ambientes de produção.

---

**Desenvolvido com ❤️ para segurança corporativa**
