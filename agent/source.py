"""Where the agent reads a platform's transactions and balances. Configured in config/platform.yaml.

A platform latches on by mapping its own table and column names; its code never changes. Every row comes
out in one shape, amounts in integer paise:
    row_id, txn_id, txn_time, from_account, to_account, amount_paise, from_balance_paise, to_balance_paise
A missing side (deposit / withdrawal) becomes "external"; balances the platform doesn't store are None.
"""

import re
import sqlite3
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

EXTERNAL = "external"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _ident(name):
    if not isinstance(name, str) or not IDENT.match(name):
        raise ValueError(f"not a safe SQL identifier in config/platform.yaml: {name!r}")
    return name


def to_paise(value, unit):
    if value is None:
        return None
    if unit == "paise":
        if isinstance(value, float):
            raise TypeError("paise column returned a float")
        return int(value)
    try:
        d = Decimal(str(value)) * 100  # rupees with up to 2 decimals, e.g. DECIMAL(18,2)
    except InvalidOperation as exc:
        raise ValueError(f"amount {value!r} is not a number") from exc
    if d != d.to_integral_value():
        raise ValueError(f"amount {value!r} has more than 2 decimals")
    return int(d)


def to_time(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(value)


class Source:
    paramstyle = "?"

    def __init__(self, cfg):
        t, a = cfg["transactions"], cfg["accounts"]
        self.t_table, self.a_table = _ident(t["table"]), _ident(a["table"])
        c = t["columns"]
        self.cols = {k: _ident(c[k]) if c.get(k) else None for k in
                     ("row_id", "txn_id", "time", "from_account", "to_account", "amount", "from_balance", "to_balance")}
        for need in ("row_id", "time", "from_account", "to_account", "amount"):
            if not self.cols[need]:
                raise ValueError(f"config/platform.yaml: transactions.columns.{need} is required")
        self.where = t.get("where") or ""  # trusted admin config, e.g. "status = 'completed'"
        self.amount_unit = t.get("amount_unit", "paise")
        self.txn_prefix = t.get("txn_id_prefix", "txn-")
        self.a_id, self.a_balance = _ident(a["id"]), _ident(a["balance"])
        self.balance_unit = a.get("balance_unit", "paise")

    # subclasses implement _query(sql, params) -> list[dict]

    def _select(self):
        cols = [f"{v} AS {k}" for k, v in self.cols.items() if v]
        return f"SELECT {', '.join(cols)} FROM {self.t_table}"

    def _filter(self, cond):
        return f" WHERE {cond}" + (f" AND ({self.where})" if self.where else "")

    def _norm(self, r):
        acct = lambda v: EXTERNAL if v is None else str(v)
        return {
            "row_id": int(r["row_id"]),
            "txn_id": str(r["txn_id"]) if r.get("txn_id") is not None else f"{self.txn_prefix}{r['row_id']}",
            "txn_time": to_time(r["time"]),
            "from_account": acct(r["from_account"]),
            "to_account": acct(r["to_account"]),
            "amount_paise": to_paise(r["amount"], self.amount_unit),
            "from_balance_paise": to_paise(r.get("from_balance"), self.balance_unit),
            "to_balance_paise": to_paise(r.get("to_balance"), self.balance_unit),
        }

    def new_rows(self, after_row_id, limit):
        p = self.paramstyle
        sql = self._select() + self._filter(f"{self.cols['row_id']} > {p}") + f" ORDER BY {self.cols['row_id']} LIMIT {int(limit)}"
        return [self._norm(r) for r in self._query(sql, (after_row_id,))]

    def rows_by_ids(self, row_ids):
        if not row_ids:
            return []
        marks = ", ".join(self.paramstyle for _ in row_ids)
        sql = self._select() + self._filter(f"{self.cols['row_id']} IN ({marks})")
        return [self._norm(r) for r in self._query(sql, tuple(row_ids))]

    def rows_by_txn_ids(self, txn_ids):
        """{txn_id: row} for the given txn ids, as the bank holds them now."""
        ids = [t for t in txn_ids if t]
        if not ids:
            return {}
        if self.cols["txn_id"]:
            marks = ", ".join(self.paramstyle for _ in ids)
            rows = self._query(self._select() + self._filter(f"{self.cols['txn_id']} IN ({marks})"), tuple(ids))
        else:  # txn ids are derived from the row id
            nums = [int(t[len(self.txn_prefix):]) for t in ids if t.startswith(self.txn_prefix) and t[len(self.txn_prefix):].isdigit()]
            rows = self._query(self._select() + self._filter(
                f"{self.cols['row_id']} IN ({', '.join(self.paramstyle for _ in nums)})"), tuple(nums)) if nums else []
        return {n["txn_id"]: n for n in (self._norm(r) for r in rows)}

    def balance(self, account):
        p = self.paramstyle
        rows = self._query(f"SELECT {self.a_balance} AS balance FROM {self.a_table} "
                           f"WHERE CAST({self.a_id} AS TEXT) = {p}", (str(account),))
        return to_paise(rows[0]["balance"], self.balance_unit) if rows else None

    def balance_as_of(self, account, after_row_id, extra_row_ids, exclude_row_ids):
        """Balance the witness should have: the bank's balance now, minus every committed row it hasn't
        accepted yet (rows after after_row_id, plus extra_row_ids). Read from ONE snapshot, so a transfer
        committing mid-question can't make an honest bank look tampered."""
        p = self.paramstyle
        queries = [(f"SELECT {self.a_balance} AS balance FROM {self.a_table} WHERE CAST({self.a_id} AS TEXT) = {p}",
                    (str(account),)),
                   (self._select() + self._filter(f"{self.cols['row_id']} > {p}"), (after_row_id,))]
        extra = sorted(set(extra_row_ids))
        if extra:
            queries.append((self._select() + self._filter(
                f"{self.cols['row_id']} IN ({', '.join(p for _ in extra)})"), tuple(extra)))
        results = self._snapshot(queries)
        if not results[0]:
            return None
        unseen = [self._norm(r) for rows in results[1:] for r in rows]
        unseen = [r for r in unseen if r["row_id"] not in exclude_row_ids]
        return self.balance_at(to_paise(results[0][0]["balance"], self.balance_unit), account, unseen)

    @staticmethod
    def balance_at(bal, account, unsealed):
        for r in unsealed:
            if r["from_account"] == account:
                bal += r["amount_paise"]
            if r["to_account"] == account:
                bal -= r["amount_paise"]
        return bal


class SqliteSource(Source):
    def __init__(self, cfg):
        super().__init__(cfg)
        self.path = cfg["path"]

    def _query(self, sql, params):
        return self._snapshot([(sql, params)])[0]

    def _snapshot(self, queries):
        conn = sqlite3.connect(self.path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN")  # one read transaction = one consistent snapshot
            return [[dict(r) for r in conn.execute(sql, params)] for sql, params in queries]
        finally:
            conn.close()


class PostgresSource(Source):
    paramstyle = "%s"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.dsn = cfg["dsn"]
        self.conn = None

    def _query(self, sql, params):
        return self._snapshot([(sql, params)])[0]

    def _snapshot(self, queries):
        import psycopg
        from psycopg.rows import dict_row
        for attempt in (1, 2):
            try:
                if self.conn is None or self.conn.closed:
                    self.conn = psycopg.connect(self.dsn, autocommit=True, row_factory=dict_row)
                with self.conn.transaction(), self.conn.cursor() as cur:
                    cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    out = []
                    for sql, params in queries:
                        cur.execute(sql, params)
                        out.append(cur.fetchall())
                    return out
            except psycopg.OperationalError:
                self.conn = None
                if attempt == 2:
                    raise
        return []


def build(cfg):
    kind = cfg.get("kind", "sqlite")
    if kind == "sqlite":
        return SqliteSource(cfg)
    if kind == "postgres":
        return PostgresSource(cfg)
    raise ValueError(f"config/platform.yaml: unknown source kind {kind!r}")
