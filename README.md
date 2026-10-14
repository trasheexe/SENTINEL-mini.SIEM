# 🛡️ SENTINEL SIEM

**Sistema de Monitoramento e Detecção de Eventos de Segurança — CLI em Python**

O **SENTINEL SIEM** é uma ferramenta de cibersegurança defensiva desenvolvida em Python, com execução diretamente pelo terminal.

O projeto tem como objetivo coletar, armazenar e analisar logs de segurança, identificando comportamentos suspeitos e gerando alertas para auxiliar no monitoramento de sistemas e na investigação de possíveis incidentes.

A ferramenta é inspirada no conceito de **SIEM (Security Information and Event Management)**, utilizando uma arquitetura simplificada para fins educacionais.

## 🚀 Funcionalidades

- **Importação de logs:** leitura de eventos em arquivos JSONL.
- **Análise de segurança:** processamento de registros armazenados.
- **Detecção de ameaças:** identificação de padrões suspeitos de autenticação.
- **Classificação de alertas:** categorização das ocorrências por severidade.
- **Histórico de eventos:** armazenamento dos registros em SQLite.
- **Estatísticas:** visualização da quantidade de eventos e alertas.
- **Exportação de relatórios:** geração de arquivos JSON.
- **Integração com HydroControl:** coletor PostgreSQL para importar registros de auditoria.

### 🔎 Regras de detecção

| Regra | Descrição | Severidade |
|---|---|---|
| Falhas repetidas | Cinco tentativas de login malsucedidas em cinco minutos, na mesma origem | Alta |
| Login após falhas | Autenticação bem-sucedida após três ou mais falhas recentes na mesma origem | Média |

As detecções são baseadas em regras simples e podem apresentar falsos positivos.

## 🛠️ Tecnologias utilizadas

| Tecnologia | Finalidade |
|---|---|
| Python 3 | Desenvolvimento da ferramenta |
| SQLite | Armazenamento local |
| JSON / JSONL | Formato dos eventos e relatórios |
| Psycopg 3 | Conexão com PostgreSQL |
| PostgreSQL | Fonte de eventos do HydroControl |
| PowerShell | Execução no Windows |

O projeto utiliza somente bibliotecas nativas do Python em seu módulo principal. A integração com PostgreSQL requer a instalação do Psycopg.

## 📁 Estrutura do projeto

```text
SENTINEL-SIEM/
│
├── main.py                 # Aplicação principal
├── hydro_collector.py      # Coletor do HydroControl
│
├── data/
│   └── sentinel.db         # Banco SQLite gerado
│
├── logs/
│   └── exemplo.jsonl       # Eventos para testes
│
├── reports/                # Relatórios exportados
│
└── README.md
```

Os diretórios e arquivos de dados podem ser criados automaticamente durante a execução.

## 💻 Instalação

### 1. Requisitos

- Python 3.10 ou superior.
- Windows, Linux ou macOS.
- Acesso ao terminal.
- PostgreSQL acessível, caso utilize o coletor HydroControl.

### 2. Preparar o ambiente

Clone o repositório, quando estiver publicado no GitHub, e entre na pasta do projeto.

Opcionalmente, crie um ambiente virtual:

```powershell
python -m venv .venv
```

No Windows:

```powershell
.\.venv\Scripts\python.exe -m pip install "psycopg[binary]"
```

O Psycopg é necessário somente para a integração com PostgreSQL.

### 3. Executar o SENTINEL

```powershell
python main.py
```

O menu principal será exibido:

```text
====== SENTINEL SIEM ======

1 - Importar logs
2 - Analisar eventos
3 - Visualizar alertas
4 - Estatísticas
5 - Exportar relatório
0 - Sair

sentinel >
```

## 📊 Como utilizar

**Importar logs:** selecione a opção `1` e informe o caminho do arquivo JSONL. Pressione Enter para utilizar o arquivo de exemplo.

**Analisar eventos:** selecione a opção `2` para processar os registros armazenados e executar as regras de detecção.

**Visualizar alertas:** selecione a opção `3` para consultar as ocorrências identificadas.

**Estatísticas:** selecione a opção `4` para visualizar a quantidade de eventos e alertas registrados.

**Exportar relatório:** selecione a opção `5` para gerar um relatório em JSON.

### Exemplo de resultado

```text
[OK] 6 eventos analisados;
2 alerta(s) encontrado(s).

Eventos armazenados: 6
Alertas atuais: 2

LOGIN_FAILED: 5
LOGIN_SUCCESS: 1
```

## 🔗 Integração com HydroControl

O SENTINEL possui um coletor dedicado para consultar eventos de auditoria do projeto **HydroControl**.

**Projeto integrado:**

- [HydroControl — GitHub](https://github.com/JorgeNoolasco/Control_Hydro)
- [HydroControl — Aplicação](https://controlhydro.vercel.app/login.php)

### Funcionamento da integração

```text
        HYDROCONTROL
             |
             v
      PostgreSQL / Supabase
             |
             v
       logs_auditoria
             |
             v
      hydro_collector.py
             |
             v
        SQLite local
             |
             v
        SENTINEL SIEM
             |
             v
    Análise e alertas
```

O HydroControl registra ações importantes, incluindo:

- Autenticação bem-sucedida.
- Falhas e bloqueios de login.
- Encerramento de sessões.
- Alterações de permissões.
- Cadastro e atualização de usuários.
- Alterações e exclusões de leituras.
- Redefinições de senha.

O coletor importa inicialmente eventos de autenticação, permitindo que o SENTINEL identifique comportamentos suspeitos.

### Configurar a conexão

A integração requer um usuário PostgreSQL com acesso somente de leitura aos registros necessários.

Configure a variável de ambiente `HYDRO_DATABASE_URL` com a conexão restrita do Supabase.

**Execute o coletor:**

```powershell
python hydro_collector.py
```

Depois execute a aplicação principal:

```powershell
python main.py
```

**Status da integração:** em desenvolvimento. O coletor foi implementado, mas a conexão real com o banco remoto ainda depende de validação em um ambiente com acesso de rede apropriado.

Nenhuma credencial de produção deve ser publicada no repositório.

## 🔐 Segurança

O SENTINEL foi desenvolvido para análise defensiva de eventos.

Recomendações:

- Utilize exclusivamente logs de sistemas próprios ou autorizados.
- Não armazene senhas, tokens de autenticação ou cookies nos registros.
- Utilize usuários de banco com permissões mínimas.
- Proteja os arquivos SQLite e relatórios exportados.
- Evite publicar arquivos contendo informações pessoais.
- Não utilize dados reais de produção para testes desnecessários.
- Configure políticas de retenção para logs e relatórios.

O projeto é uma ferramenta educacional e não substitui uma solução SIEM corporativa.

## 🗺️ Roadmap

- [x] Interface de linha de comando.
- [x] Importação de logs JSONL.
- [x] Armazenamento em SQLite.
- [x] Regras iniciais de detecção.
- [x] Visualização de alertas.
- [x] Estatísticas de eventos.
- [x] Exportação de relatórios.
- [x] Desenvolvimento inicial do coletor HydroControl.
- [ ] Validação da integração real com Supabase.
- [ ] Monitoramento contínuo de novos eventos.
- [ ] Detecção de atividades suspeitas em diferentes tipos de logs.
- [ ] Análise de eventos de segurança do Windows.
- [ ] Correlação de eventos entre diferentes fontes.
- [ ] Prevenção de importações duplicadas.
- [ ] Testes automatizados.
- [ ] Melhorias na interface CLI.

## 🎯 Objetivo educacional

O SENTINEL SIEM foi criado para aprofundar conhecimentos em:

- Cibersegurança defensiva (Blue Team).
- Monitoramento de eventos de segurança.
- Análise de logs.
- Detecção de comportamentos suspeitos.
- Programação Python.
- Bancos de dados SQL.
- Investigação e resposta a incidentes.

O projeto está em desenvolvimento e receberá melhorias progressivas.

---

**SENTINEL SIEM — Monitoramento, análise e detecção de eventos de segurança.**

Desenvolvido para fins educacionais e uso em ambientes autorizados.