"""Importa auditoria do HydroControl (PostgreSQL) para o SQLite do SENTINEL.
Requer: pip install 'psycopg[binary]'
Configure HYDRO_DATABASE_URL com uma credencial PostgreSQL SOMENTE LEITURA.
Execute na pasta do main.py: python hydro_collector.py
"""
import os
import sqlite3
from pathlib import Path

try:
    import psycopg
except ImportError as exc:
    raise SystemExit("Instale: python -m pip install 'psycopg[binary]'") from exc

ROOT = Path(__file__).resolve().parent
DB = ROOT / 'data' / 'sentinel.db'
BATCH_SIZE = 500
EVENT_MAP = {
    'login_falha': 'LOGIN_FAILED',
    'login_sucesso': 'LOGIN_SUCCESS',
}


def main():
    dsn = os.environ.get('HYDRO_DATABASE_URL', '').strip()
    if not dsn:
        raise SystemExit('Configure HYDRO_DATABASE_URL com a conexão de leitura do Supabase.')
    DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as local:
        local.execute('''CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            usuario TEXT NOT NULL,
            evento TEXT NOT NULL,
            origem TEXT NOT NULL)''')
        local.execute('''CREATE TABLE IF NOT EXISTS hydro_importados (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL)''')
        local.execute('''CREATE TABLE IF NOT EXISTS hydro_cursor (
            origem TEXT PRIMARY KEY,
            criado_em TEXT NOT NULL,
            id TEXT NOT NULL)''')
        last = local.execute(
            'SELECT criado_em, id FROM hydro_cursor WHERE origem = ?', ('hydro',)
        ).fetchone()
        added = 0
        with psycopg.connect(dsn, connect_timeout=10, options='-c default_transaction_read_only=on') as remote:
            with remote.cursor() as cur:
                while True:
                    if last:
                        # ID e timestamp ordenados juntos para lidar com horários repetidos.
                        cur.execute('''
                            SELECT id, criado_em, acao, usuario_id, ip_hash
                            FROM public.logs_auditoria
                            WHERE (criado_em, id) > (%s::timestamptz, %s::bigint)
                            ORDER BY criado_em, id LIMIT %s
                        ''', (last[0], last[1], BATCH_SIZE))
                    else:
                        cur.execute('''
                            SELECT id, criado_em, acao, usuario_id, ip_hash
                            FROM public.logs_auditoria
                            ORDER BY criado_em, id LIMIT %s
                        ''', (BATCH_SIZE,))
                    rows = cur.fetchall()
                    if not rows:
                        break
                    with local:
                        for id_, timestamp, acao, usuario, ip_hash in rows:
                            event = EVENT_MAP.get(acao)
                            if event:
                                cursor = local.execute(
                                    'INSERT OR IGNORE INTO hydro_importados (id, timestamp) VALUES (?, ?)',
                                    (str(id_), timestamp.isoformat())
                                )
                                if cursor.rowcount:
                                    local.execute('''INSERT INTO eventos
                                        (timestamp, ip, usuario, evento, origem)
                                        VALUES (?, ?, ?, ?, ?)''', (
                                        timestamp.isoformat(),
                                        str(ip_hash or 'sem-ip-hash'),
                                        str(usuario or 'nao-identificado'), event, 'hydro'
                                    ))
                                    added += 1
                        last = (rows[-1][1].isoformat(), str(rows[-1][0]))
                        local.execute('''INSERT INTO hydro_cursor (origem, criado_em, id)
                            VALUES (?, ?, ?) ON CONFLICT(origem) DO UPDATE SET
                            criado_em=excluded.criado_em, id=excluded.id''', ('hydro', *last))
                    if len(rows) < BATCH_SIZE:
                        break
    print(f'[OK] {added} novo(s) evento(s) de login importado(s) do HydroControl.')
    print('Execute main.py e selecione 2 para analisar os eventos.')


if __name__ == '__main__':
    main()
