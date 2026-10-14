"""SENTINEL SIEM - protótipo defensivo para logs JSONL locais.

Execute: python main.py
Somente biblioteca padrão do Python.
"""
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
LOGS = BASE / "logs"
DB = DATA / "sentinel.db"
REPORTS = BASE / "reports"


def conectar():
    DATA.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            usuario TEXT NOT NULL,
            evento TEXT NOT NULL,
            origem TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            regra TEXT NOT NULL,
            severidade TEXT NOT NULL,
            ip TEXT NOT NULL,
            descricao TEXT NOT NULL,
            criado_em TEXT NOT NULL
        );
    """)
    conn.commit()
    return conn


def interpretar_evento(obj, origem):
    """Valida um evento JSONL e converte timestamp para UTC."""
    if not isinstance(obj, dict):
        raise ValueError("registro deve ser um objeto JSON")
    for campo in ("timestamp", "ip", "usuario", "evento"):
        if not isinstance(obj.get(campo), str) or not obj[campo].strip():
            raise ValueError(f"campo ausente ou inválido: {campo}")
    instante = datetime.fromisoformat(obj["timestamp"].replace("Z", "+00:00"))
    if instante.tzinfo is None:
        raise ValueError("timestamp precisa conter fuso horário")
    instante = instante.astimezone(timezone.utc)
    evento = obj["evento"].strip().upper()
    if evento not in {"LOGIN_FAILED", "LOGIN_SUCCESS"}:
        raise ValueError("evento não reconhecido")
    return (instante.isoformat(), obj["ip"].strip()[:64],
            obj["usuario"].strip()[:100], evento, origem)


def importar_logs(conn):
    LOGS.mkdir(exist_ok=True)
    nome = input("Caminho do arquivo .jsonl (Enter: logs/exemplo.jsonl): ").strip()
    caminho = Path(nome) if nome else LOGS / "exemplo.jsonl"
    if caminho.suffix.lower() != ".jsonl" or not caminho.is_file():
        print("[ERRO] Escolha um arquivo .jsonl existente.")
        return
    importados = erros = 0
    with caminho.open(encoding="utf-8-sig") as arquivo:
        for numero, linha in enumerate(arquivo, 1):
            if not linha.strip():
                continue
            try:
                obj = json.loads(linha)
                evento = interpretar_evento(obj, caminho.name)
                conn.execute("""INSERT INTO eventos
                  (timestamp, ip, usuario, evento, origem) VALUES (?, ?, ?, ?, ?)""", evento)
                importados += 1
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                erros += 1
                print(f"[AVISO] Linha {numero} ignorada: {exc}")
    conn.commit()
    print(f"[OK] {importados} evento(s) importado(s); {erros} linha(s) inválida(s).")


def analisar(conn):
    """Detecta >=5 falhas do mesmo IP em 5 minutos e sucesso após >=3 falhas."""
    registros = conn.execute("""SELECT timestamp, ip, usuario, evento FROM eventos
        ORDER BY timestamp, id""").fetchall()
    por_ip = defaultdict(list)
    for r in registros:
        por_ip[r["ip"]].append((datetime.fromisoformat(r["timestamp"]), r["evento"]))

    agora = datetime.now(timezone.utc).isoformat()
    alertas = []
    for ip, registros_ip in por_ip.items():
        falhas = []
        inicio_alerta = None
        for instante, tipo in registros_ip:
            limite = instante - timedelta(minutes=5)
            falhas = [x for x in falhas if x >= limite]
            if tipo == "LOGIN_FAILED":
                falhas.append(instante)
                if len(falhas) >= 5 and inicio_alerta is None:
                    descricao = f"{len(falhas)} falhas de login em até 5 minutos"
                    alertas.append(("FALHAS_REPETIDAS", "ALTA", ip, descricao, agora))
                    inicio_alerta = instante
            elif tipo == "LOGIN_SUCCESS":
                if len(falhas) >= 3:
                    alertas.append(("SUCESSO_APOS_FALHAS", "MEDIA", ip,
                                    f"Login bem-sucedido após {len(falhas)} falhas recentes", agora))
                falhas.clear()
                inicio_alerta = None
            if inicio_alerta is not None and instante - inicio_alerta > timedelta(minutes=5):
                inicio_alerta = None
    # Reanalisar substitui os alertas calculados, evitando duplicação.
    with conn:
        conn.execute("DELETE FROM alertas")
        conn.executemany("""INSERT INTO alertas
          (regra, severidade, ip, descricao, criado_em) VALUES (?, ?, ?, ?, ?)""", alertas)
    print(f"[OK] {len(registros)} eventos analisados; {len(alertas)} alerta(s) encontrado(s).")


def listar_alertas(conn):
    linhas = conn.execute("SELECT * FROM alertas ORDER BY id DESC LIMIT 30").fetchall()
    if not linhas:
        print("Nenhum alerta. Importe logs e execute a análise.")
    for a in linhas:
        print(f"#{a['id']} [{a['severidade']}] {a['regra']} | IP: {a['ip']}")
        print(f"   {a['descricao']}")


def estatisticas(conn):
    eventos = conn.execute("SELECT COUNT(*) FROM eventos").fetchone()[0]
    alertas = conn.execute("SELECT COUNT(*) FROM alertas").fetchone()[0]
    print(f"Eventos armazenados: {eventos} | Alertas atuais: {alertas}")
    for r in conn.execute("SELECT evento, COUNT(*) AS total FROM eventos GROUP BY evento"):
        print(f"  {r['evento']}: {r['total']}")


def exportar(conn):
    REPORTS.mkdir(exist_ok=True)
    destino = REPORTS / "alertas.json"
    dados = [dict(a) for a in conn.execute("SELECT * FROM alertas ORDER BY id")]
    destino.write_text(json.dumps(dados, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Relatório salvo em {destino}")


def criar_exemplo():
    LOGS.mkdir(exist_ok=True)
    destino = LOGS / "exemplo.jsonl"
    if destino.exists():
        return
    base = datetime.now(timezone.utc) - timedelta(minutes=2)
    dados = [
        {"timestamp": (base + timedelta(seconds=i * 10)).isoformat(),
         "ip": "192.0.2.10", "usuario": "teste", "evento": "LOGIN_FAILED"}
        for i in range(5)
    ]
    dados.append({"timestamp": (base + timedelta(seconds=55)).isoformat(),
                  "ip": "192.0.2.10", "usuario": "teste", "evento": "LOGIN_SUCCESS"})
    destino.write_text("\n".join(json.dumps(x) for x in dados) + "\n", encoding="utf-8")


def main():
    criar_exemplo()
    with conectar() as conn:
        while True:
            print("\n====== SENTINEL SIEM ======")
            print("1 - Importar logs")
            print("2 - Analisar eventos")
            print("3 - Visualizar alertas")
            print("4 - Estatísticas")
            print("5 - Exportar relatório")
            print("0 - Sair")
            escolha = input("sentinel > ").strip()
            try:
                if escolha == "1": importar_logs(conn)
                elif escolha == "2": analisar(conn)
                elif escolha == "3": listar_alertas(conn)
                elif escolha == "4": estatisticas(conn)
                elif escolha == "5": exportar(conn)
                elif escolha == "0": break
                else: print("Opção inválida.")
            except (OSError, sqlite3.Error, UnicodeError) as exc:
                print(f"[ERRO] Operação não concluída: {exc}")


if __name__ == "__main__":
    main()
