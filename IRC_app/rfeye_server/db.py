"""
PostgreSQL persistence for the RFeye IRC server.

The in-memory models (NodeStore/IncidentLog/AuditLog) stay the fast path
the dashboard reads from — this module write-throughs the same events to
Postgres so incident history survives a server restart, and loads it back
on boot. All methods are async (asyncpg) so they can be scheduled from the
asyncio event loop without blocking the UDP/WebSocket handlers.

Requires: pip install asyncpg
Schema:   psql "$DATABASE_URL" -f schema.sql   (run once before first start)
"""
import logging

import asyncpg

log = logging.getLogger("rfeye")


class PostgresStore:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: asyncpg.Pool = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(self.dsn, min_size=1, max_size=5)
        log.info("Postgres connected")

    async def close(self):
        if self.pool:
            await self.pool.close()

    # ── nodes ──

    async def upsert_node(self, node_id, name, lat, lon, online=True, battery=None, mic_status=None):
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO nodes (id, name, lat, lon, battery, mic_status, last_seen, online)
                VALUES ($1, $2, $3, $4, $5, $6, now(), $7)
                ON CONFLICT (id) DO UPDATE
                    SET name = $2, lat = $3, lon = $4,
                        battery = COALESCE($5, nodes.battery),
                        mic_status = COALESCE($6, nodes.mic_status),
                        last_seen = now(), online = $7
                """,
                node_id, name, lat, lon, battery, mic_status, online,
            )

    async def touch_node(self, node_id, online=True):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE nodes SET last_seen = now(), online = $2 WHERE id = $1",
                node_id, online,
            )

    async def set_nodes_offline(self, node_ids: list):
        if not node_ids:
            return
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE nodes SET online = false WHERE id = ANY($1::text[])",
                node_ids,
            )

    async def load_nodes(self) -> list:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM nodes")
            return [dict(r) for r in rows]

    # ── incidents ──

    async def insert_incident(self, incident: dict):
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO incidents
                    (id, node_id, node_name, classification, confidence,
                     angle, tdoa12, tdoa13, lat, lon,
                     confirming_nodes, total_nodes, status)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                ON CONFLICT (id) DO NOTHING
                """,
                incident["id"], incident["node_id"], incident["node"],
                incident.get("classification"), incident.get("confidence"),
                incident.get("angle"), incident.get("tdoa12"), incident.get("tdoa13"),
                incident.get("lat"), incident.get("lon"),
                incident.get("confirming_nodes"), incident.get("total_nodes"),
                incident.get("status", "open"),
            )

    async def update_incident_status(self, incident_id, status):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE incidents SET status = $2, updated_at = now() WHERE id = $1",
                incident_id, status,
            )

    async def load_recent_incidents(self, n=100) -> list:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT $1", n
            )
            return [dict(r) for r in reversed(rows)]   # oldest-first, matching in-memory order

    # ── audit log ──

    async def add_audit_entry(self, incident_id, severity, message):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO incident_audit_log (incident_id, severity, message) VALUES ($1,$2,$3)",
                incident_id, severity, message,
            )

    async def load_recent_audit(self, n=50) -> list:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM incident_audit_log ORDER BY ts DESC LIMIT $1", n
            )
            return [dict(r) for r in reversed(rows)]
