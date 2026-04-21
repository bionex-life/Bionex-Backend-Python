# Bionex Enterprise Architecture & Service Configuration

**Version:** 1.0  
**Date:** April 18, 2026  
**Target:** Enterprise-Grade Healthcare System (UK NHS Compliant)  
**Deployment:** Docker + Kubernetes on AWS / Azure / On-Premise

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Service Stack](#service-stack)
3. [Detailed Service Configuration](#detailed-service-configuration)
4. [Data Flow Architecture](#data-flow-architecture)
5. [Deployment Architecture](#deployment-architecture)
6. [Security & Compliance](#security--compliance)
7. [Monitoring & Observability](#monitoring--observability)
8. [Disaster Recovery & Backup](#disaster-recovery--backup)
9. [Cost Analysis](#cost-analysis)
10. [Implementation Timeline](#implementation-timeline)

---

## Architecture Overview

### System Architecture (High-Level)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BIONEX ENTERPRISE SYSTEM                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Patient App  │  │ Doctor App   │  │ Admin Portal │  │ API Clients  │    │
│  │ (iOS/Android)│  │ (iOS/Android)│  │ (Web)        │  │ (3rd-party)  │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                  │                  │                │             │
│         │                  │ HTTPS / TLS 1.3  │                │             │
│         └──────────────────┴──────────────────┴────────────────┘             │
│                              │                                               │
│                    ┌─────────▼──────────┐                                   │
│                    │   API Gateway      │                                   │
│                    │ (Kong / AWS API GW)│                                   │
│                    │  - Rate Limiting   │                                   │
│                    │  - Auth Validation │                                   │
│                    │  - Request Logging │                                   │
│                    └────────┬───────────┘                                   │
│                             │                                               │
│            ┌────────────────┼────────────────┐                             │
│            │                │                │                             │
│     ┌──────▼──────┐  ┌──────▼──────┐  ┌─────▼──────────┐                  │
│     │  API Pod 1  │  │  API Pod 2  │  │   API Pod N    │                  │
│     │ (FastAPI)   │  │ (FastAPI)   │  │  (FastAPI)     │                  │
│     │  - Keys API │  │  - Keys API │  │  - Keys API    │                  │
│     │  - Records  │  │  - Records  │  │  - Records     │                  │
│     │  - Sharing  │  │  - Sharing  │  │  - Sharing     │                  │
│     │  - Audit    │  │  - Audit    │  │  - Audit       │                  │
│     └──────┬──────┘  └──────┬──────┘  └────┬───────────┘                  │
│            │                │              │                              │
│            └────────────────┼──────────────┘                              │
│                             │                                            │
│       ┌─────────────────────┼─────────────────────┐                     │
│       │                     │                     │                     │
│   ┌───▼────────────┐   ┌────▼─────────────┐   ┌──▼──────────────┐     │
│   │  PostgreSQL    │   │  Redis Cache     │   │  RabbitMQ       │     │
│   │  (Primary DB)  │   │  (Hot Cache)     │   │  (Message Queue)│     │
│   │  - Encrypted   │   │  - PKs           │   │  - Async Jobs   │     │
│   │  - Indexed     │   │  - Session Keys  │   │  - Notifications│     │
│   │  - Replicated  │   │  - Permissions   │   │  - Audit Logs   │     │
│   └────────────────┘   └──────────────────┘   └─────────────────┘     │
│                             │                     │                     │
│                             └─────────────────────┘                     │
│                                     │                                  │
│       ┌─────────────────────────────▼──────────────────────────────┐  │
│       │              Async Job Workers (Celery)                    │  │
│       │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│       │  │ Worker 1     │  │ Worker 2     │  │  Worker N    │    │  │
│       │  │ - Signatures │  │ - Signatures │  │ - Signatures │    │  │
│       │  │ - Rotation   │  │ - Rotation   │  │ - Rotation   │    │  │
│       │  │ - Emails     │  │ - Emails     │  │ - Emails     │    │  │
│       │  └──────────────┘  └──────────────┘  └──────────────┘    │  │
│       └─────────────────────────────────────────────────────────┘  │
│                                     │                                │
│       ┌─────────────────────────────▼──────────────────────────┐   │
│       │           External Services                            │   │
│       │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │   │
│       │  │  HashiCorp  │  │ Prometheus  │  │  ELK Stack  │    │   │
│       │  │   Vault     │  │  / Grafana  │  │ (Logs)      │    │   │
│       │  │ (Secrets)   │  │ (Metrics)   │  │             │    │   │
│       │  └─────────────┘  └─────────────┘  └─────────────┘    │   │
│       └──────────────────────────────────────────────────────┘   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## Service Stack

### Core Services

| Service | Purpose | Why This Choice | Scale |
|---------|---------|-----------------|-------|
| **PostgreSQL 15** | Primary Database | ACID, encryption, replication | Master-Replica |
| **Redis 7** | Cache + Session Store | Ultra-fast, in-memory, TTL support | Sentinel (HA) |
| **RabbitMQ** | Message Queue | Durable, reliable, healthcare-grade | Cluster (3 nodes) |
| **Celery** | Job Queue Worker | Distributed tasks, scheduling, retries | 5-10 workers |
| **HashiCorp Vault** | Secrets Management | HSM support, audit logs, key rotation | HA setup |
| **Kong** | API Gateway | Rate limiting, auth, logging, plugins | Cluster (3 nodes) |
| **Prometheus** | Metrics | Industry standard, time-series DB | With AlertManager |
| **Grafana** | Visualization | Real-time dashboards, alerts | High HA |
| **ELK Stack** | Log Aggregation | Elasticsearch + Logstash + Kibana | Cluster (3 nodes) |
| **Nginx / HAProxy** | Load Balancer | SSL termination, reverse proxy | Active-Passive |

---

## Detailed Service Configuration

### 1. PostgreSQL 15 (Primary Database)

**Why PostgreSQL?**
- Native UUID support (your entire schema uses UUIDs)
- JSONB for flexible audit logs
- Full-text search (for medical records)
- Replication (HA)
- pgcrypto extension for encryption
- FIPS 140-2 compliance available

#### Configuration

```yaml
# docker-compose production snippet
postgres:
  image: postgres:15-alpine
  environment:
    POSTGRES_DB: bionex
    POSTGRES_USER: bionex
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}  # From Vault
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - ./pg_config/postgresql.conf:/etc/postgresql/postgresql.conf
    - ./pg_config/pg_hba.conf:/etc/postgresql/pg_hba.conf
  command:
    - "postgres"
    - "-c"
    - "config_file=/etc/postgresql/postgresql.conf"
  ports:
    - "5432:5432"
  networks:
    - bionex-network
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U bionex"]
    interval: 10s
    timeout: 5s
    retries: 5
```

#### postgresql.conf (Key Settings)

```ini
# ─── Performance ────────────────────────────────────────
max_connections = 200              # Handle 100-150 concurrent API clients
shared_buffers = 256MB             # 25% of system RAM
effective_cache_size = 1024MB      # 100% of system RAM
work_mem = 4MB                     # Per operation
maintenance_work_mem = 64MB        # For VACUUM, reindex

# ─── Replication (Primary) ──────────────────────────────
wal_level = replica                # Enable replication
max_wal_senders = 3                # Allow 3 replica connections
max_replication_slots = 3

# ─── Encryption at Rest ─────────────────────────────────
# On filesystem: Use dm-crypt or AWS EBS encryption
# In DB: Use pgcrypto extension

# ─── Logging ─────────────────────────────────────────────
log_statement = 'all'              # Log all queries (for audit)
log_duration = on                  # Log query duration
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_checkpoints = on
log_connections = on
log_disconnections = on

# ─── SSL/TLS ─────────────────────────────────────────────
ssl = on
ssl_cert_file = '/etc/ssl/certs/postgres.crt'
ssl_key_file = '/etc/ssl/private/postgres.key'
ssl_protocols = 'TLSv1.3'
```

#### Connection String

```bash
# From app/config.py
DATABASE_URL = "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:5432/${POSTGRES_DB}?sslmode=require"

# Example production
DATABASE_URL = "postgresql://bionex:secure_pass@postgres-primary.bionex-prod:5432/bionex?sslmode=require"
```

#### Replication Setup (Master-Replica)

**Master (Primary) Node:**
```bash
docker-compose up postgres-primary
```

**Replica Node:**
```bash
# Point replica to primary
docker-compose up postgres-replica

# Replica automatically syncs WAL logs from primary
# If primary fails, promote replica:
pg_ctl promote -D /var/lib/postgresql/data
```

#### Backup Strategy

```bash
#!/bin/bash
# Daily backup via pg_dump (encrypted, stored in S3)

BACKUP_DIR=/backups/postgresql
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PASSWORD=${POSTGRES_PASSWORD}

pg_dump -h postgres-primary \
  -U bionex \
  -d bionex \
  --format=custom \
  --verbose \
  --file=${BACKUP_DIR}/bionex_${TIMESTAMP}.dump

# Encrypt backup with GPG
gpg --symmetric \
  --cipher-algo AES256 \
  --output ${BACKUP_DIR}/bionex_${TIMESTAMP}.dump.gpg \
  ${BACKUP_DIR}/bionex_${TIMESTAMP}.dump

# Upload to S3
aws s3 cp ${BACKUP_DIR}/bionex_${TIMESTAMP}.dump.gpg \
  s3://bionex-backups/postgresql/

# Cleanup
rm ${BACKUP_DIR}/bionex_${TIMESTAMP}.dump
```

---

### 2. Redis 7 (Cache + Session Store)

**Why Redis?**
- Sub-millisecond latency (perfect for your 18ms target)
- Built-in TTL expiration (session keys)
- Pub/Sub for real-time notifications
- Sentinel for high availability
- Cluster mode for horizontal scaling

#### Configuration

```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  command:
    - redis-server
    - "--requirepass"
    - "${REDIS_PASSWORD}"
    - "--maxmemory"
    - "2gb"
    - "--maxmemory-policy"
    - "allkeys-lru"  # LRU eviction (discard least-used)
    - "--appendonly"
    - "yes"  # Persistence
    - "--appendfsync"
    - "everysec"  # Sync to disk every second
  volumes:
    - redis_data:/data
  ports:
    - "6379:6379"
  networks:
    - bionex-network
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 5s
    timeout: 3s
    retries: 5
```

#### redis.conf (Key Settings)

```ini
# ─── Memory ──────────────────────────────────────────────
maxmemory 2gb                      # Redis max memory
maxmemory-policy allkeys-lru       # Evict LRU keys when full

# ─── Persistence ─────────────────────────────────────────
appendonly yes                     # AOF persistence
appendfsync everysec               # Sync every second
dir /data

# ─── Replication ─────────────────────────────────────────
# Master configuration
# (Replicas point here)

# ─── SSL/TLS ─────────────────────────────────────────────
port 0                             # Disable plain TCP
tls-port 6380                      # Enable TLS port
tls-cert-file /etc/redis/certs/redis.crt
tls-key-file /etc/redis/certs/redis.key
tls-protocols "TLSv1.3"
requirepass ${REDIS_PASSWORD}      # Password auth
```

#### Sentinel Configuration (High Availability)

```yaml
# sentinel-1.conf
port 26379
sentinel monitor bionex-redis 127.0.0.1 6379 2
sentinel down-after-milliseconds bionex-redis 5000
sentinel parallel-syncs bionex-redis 1
sentinel failover-timeout bionex-redis 10000
```

**What it does:**
- Monitors Redis master/replica
- Auto-failover if master dies (<5 sec detection)
- Promotes replica to master
- Notifies all clients of new master

#### Application Integration

```python
# app/config.py
from redis.sentinel import Sentinel

REDIS_SENTINEL_HOSTS = [
    ("sentinel-1:26379", 26379),
    ("sentinel-2:26379", 26379),
    ("sentinel-3:26379", 26379),
]

sentinel = Sentinel(REDIS_SENTINEL_HOSTS)
redis_client = sentinel.master_for(
    'bionex-redis',
    socket_timeout=0.1,
    db=0
)

# Usage in app:
def get_doctor_public_key(doctor_id):
    cache_key = f"doctor_pubkey:{doctor_id}"
    
    # Get from Redis
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    
    # Query DB if not cached
    key = db.query(UserKeypair).filter_by(user_id=doctor_id).first()
    redis_client.setex(cache_key, 3600, json.dumps(key.to_dict()))
    return key
```

#### Cache Keys Strategy

```python
# Define all cache keys with TTL

CACHE_KEYS = {
    # Public Keys (1 hour, changes rarely)
    "doctor_pubkey:{doctor_id}": 3600,
    "patient_pubkey:{patient_id}": 3600,
    "server_pubkey": -1,  # No expiration
    
    # Permission Status (1 hour)
    "permission:{patient_id}:{doctor_id}": 3600,
    
    # Session Key Hashes (7 days, matches key TTL)
    "session_key_hash:{sharing_token}": 604800,
    
    # Audit Log Caching (5 mins, changes frequently)
    "audit_logs:{patient_id}:{page}": 300,
    
    # Rate Limit Counters (1 minute)
    "ratelimit:{user_id}:{endpoint}": 60,
}
```

---

### 3. RabbitMQ (Message Queue)

**Why RabbitMQ?**
- Message persistence (messages survive broker restart)
- Dead-letter queues (retry failed messages)
- Multiple routing options (direct, fanout, topic)
- Priority queues (high-priority alerts first)
- Cluster for HA

#### Configuration

```yaml
# docker-compose.yml
rabbitmq:
  image: rabbitmq:3.12-management-alpine
  environment:
    RABBITMQ_DEFAULT_USER: ${RABBITMQ_USER}
    RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD}
    RABBITMQ_DEFAULT_VHOST: bionex
    RABBITMQ_ERLANG_COOKIE: bionex-secret-cookie
  volumes:
    - rabbitmq_data:/var/lib/rabbitmq
    - ./rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf
  ports:
    - "5672:5672"      # AMQP
    - "15672:15672"    # Management console
  networks:
    - bionex-network
  healthcheck:
    test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
    interval: 10s
    timeout: 5s
    retries: 5
```

#### rabbitmq.conf

```ini
# ─── Clustering ──────────────────────────────────────────
## For 3-node cluster
cluster_formation.peer_discovery_backend = dns
cluster_formation.dns.hostname = rabbitmq-cluster

# ─── Memory ───────────────────────────────────────────────
vm_memory_high_watermark.relative = 0.6
total_memory_available_override_value = 4GB

# ─── Persistence ──────────────────────────────────────────
queue_master_locator = min-masters

# ─── Management Plugin ─────────────────────────────────
management.tcp.port = 15672
management_agent.tcp.port = 15692

# ─── SSL/TLS ───────────────────────────────────────────
listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/rabbitmq/ca.crt
ssl_options.certfile = /etc/rabbitmq/cert.pem
ssl_options.keyfile = /etc/rabbitmq/key.pem
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = true
```

#### Queue Architecture

```python
# app/tasks/queues.py

# Define message queues
QUEUES = {
    # Audit Logging (high priority, must complete)
    "audit_logs": {
        "durable": True,
        "routing_key": "audit.*",
        "priority": 10,
    },
    
    # Session Key Rotation (medium priority, scheduled)
    "session_rotation": {
        "durable": True,
        "routing_key": "rotation.*",
        "priority": 5,
    },
    
    # Email Notifications (low priority, can be delayed)
    "notifications": {
        "durable": True,
        "routing_key": "notify.*",
        "priority": 1,
    },
    
    # Signature Verification (bulk, async)
    "crypto_operations": {
        "durable": True,
        "routing_key": "crypto.*",
        "priority": 3,
    },
    
    # Dead-letter queue (failed messages)
    "dead_letter": {
        "durable": True,
    },
}
```

#### Message Flow Example

```python
from celery import Celery
from kombu import Queue, Exchange

app = Celery('bionex')
app.conf.broker_url = 'amqp://bionex:password@rabbitmq:5672/bionex'
app.conf.result_backend = 'redis://redis:6379/0'

# Define exchanges
default_exchange = Exchange('bionex', type='direct', durable=True)
topic_exchange = Exchange('bionex.topic', type='topic', durable=True)

# Tasks mapped to queues
@app.task(queue='audit_logs', bind=True, max_retries=3)
def create_audit_log_signed(self, action, data, signature):
    """
    Critical: Audit log creation must succeed
    """
    try:
        # Create and sign audit log
        audit_entry = CryptographicAuditLog(
            action=action,
            event_data=data,
            event_signature=signature
        )
        db.add(audit_entry)
        db.commit()
    except Exception as exc:
        # Retry up to 3 times with exponential backoff
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)

@app.task(queue='session_rotation')
def rotate_session_keys_job():
    """
    Scheduled: Every 24 hours, rotate expiring keys
    """
    expiring_keys = db.query(SessionKey).filter(
        SessionKey.expires_at < now() + timedelta(days=1)
    ).all()
    
    for key in expiring_keys:
        # Generate new session key
        # Encrypt with doctor's public key
        # Update DB

@app.task(queue='notifications')
def send_revision_notification(doctor_id, reason):
    """
    Low priority: Can be delayed, not critical
    """
    doctor = db.query(User).filter_by(id=doctor_id).first()
    send_email(
        to=doctor.email,
        subject="Access Revoked",
        body=f"Patient revoked access: {reason}"
    )

@app.task(queue='crypto_operations', bind=True)
def verify_audit_signature_batch(self, log_ids):
    """
    Batch verify signatures (async)
    """
    for log_id in log_ids:
        log_entry = db.query(CryptographicAuditLog).get(log_id)
        is_valid = verify_ecdsa_signature(
            log_entry.event_data,
            log_entry.event_signature
        )
        log_entry.signature_verified = is_valid
    db.commit()
```

#### Celery Beat (Scheduler)

```python
# app/celery_config.py
from celery.schedules import crontab

app.conf.beat_schedule = {
    # Rotate session keys daily at 2 AM UTC
    'rotate-session-keys': {
        'task': 'app.tasks.rotate_session_keys_job',
        'schedule': crontab(hour=2, minute=0),
    },
    
    # Cleanup expired audit logs monthly
    'cleanup-audit-logs': {
        'task': 'app.tasks.cleanup_old_audit_logs',
        'schedule': crontab(day_of_month=1, hour=3, minute=0),
    },
    
    # Verify missing signatures every hour
    'verify-signatures': {
        'task': 'app.tasks.verify_audit_signatures',
        'schedule': crontab(minute=0),
    },
}
```

---

### 4. Celery Workers (Job Execution)

**Configuration**

```yaml
# docker-compose.yml - Worker Service
celery_worker:
  build: .
  command: celery -A app.celery_app worker --loglevel=info -n worker1@%h -c 4
  environment:
    CELERY_BROKER_URL: amqp://bionex:password@rabbitmq:5672/bionex
    CELERY_RESULT_BACKEND: redis://redis:6379/0
  depends_on:
    - rabbitmq
    - redis
    - postgres
  networks:
    - bionex-network
  deploy:
    replicas: 3  # 3 workers for load distribution
    resources:
      limits:
        cpus: '1'
        memory: 512M
```

**Worker Concurrency Strategy:**

```python
# For long-running tasks: Process-based (spawn)
# For I/O-bound: Gevent (async greenlets)

# celery.py
app.conf.worker_pool = 'solo'  # Or 'prefork', 'gevent', 'solo'
app.conf.worker_prefetch_multiplier = 4  # Prefetch 4 tasks
app.conf.worker_max_tasks_per_child = 1000  # Recycle worker after 1000 tasks
```

---

### 5. HashiCorp Vault (Secrets Management)

**Why Vault?**
- Centralized secret storage (API keys, DB passwords, encryption keys)
- Dynamic secrets (auto-rotate DB credentials)
- Encryption as a Service (seal/unseal data)
- Audit logs (who accessed what secret)
- HSM support (FIPS 140-2)

#### Deployment

```yaml
# docker-compose.yml
vault:
  image: vault:latest
  environment:
    VAULT_DEV_ROOT_TOKEN_ID: ${VAULT_ROOT_TOKEN}
    VAULT_ADDR: http://127.0.0.1:8200
  volumes:
    - vault_data:/vault/data
    - ./vault_config.hcl:/vault/config/config.hcl
  ports:
    - "8200:8200"
  cap_add:
    - IPC_LOCK  # Prevent secrets from being swapped to disk
  networks:
    - bionex-network
```

#### Vault Configuration (Production)

```hcl
# vault_config.hcl
backend "consul" {
  path = "bionex/"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file = "/vault/certs/vault.key"
}

ui = true
disable_mlock = false
```

#### Secrets to Store

```bash
# Initialize Vault
vault operator init -key-shares=5 -key-threshold=3

# Unseal with 3 out of 5 keys
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Login with root token
vault login <VAULT_ROOT_TOKEN>

# Create secret engines
vault secrets enable -path=bionex_db database
vault secrets enable -path=bionex_app kv

# Store secrets
vault kv put bionex_app/postgres \
  username=bionex \
  password=<secure_password>

vault kv put bionex_app/jwt \
  secret_key=<jwt_secret>

vault kv put bionex_app/encryption \
  field_encryption_key=<fernet_key>

vault kv put bionex_app/rabbitmq \
  username=bionex \
  password=<rabbitmq_password>

vault kv put bionex_app/redis \
  password=<redis_password>
```

#### Application Integration

```python
# app/config.py
import hvac

class Settings(BaseSettings):
    # Initialize Vault client
    vault_client = hvac.Client(
        url='https://vault.bionex.local:8200',
        token=os.getenv('VAULT_TOKEN')
    )
    
    # Fetch secrets at startup
    @property
    def DATABASE_PASSWORD(self):
        secret = self.vault_client.secrets.kv.v2.read_secret_version(
            path='postgres'
        )
        return secret['data']['data']['password']
    
    @property
    def SECRET_KEY(self):
        secret = self.vault_client.secrets.kv.v2.read_secret_version(
            path='jwt'
        )
        return secret['data']['data']['secret_key']
    
    # Rotate secrets every 90 days
    def rotate_secrets(self):
        # Called by scheduled task
        new_password = generate_strong_password()
        self.vault_client.secrets.kv.v2.update_secret_version(
            path='postgres',
            secret_data={'password': new_password}
        )
```

---

### 6. Kong API Gateway

**Why Kong?**
- Rate limiting per user/API key
- Authentication (JWT, OAuth2, API Key)
- Request/Response logging
- SSL/TLS termination
- Plugins for advanced features
- Cluster for HA

#### Configuration

```yaml
# docker-compose.yml
kong_db:
  image: postgres:15-alpine
  environment:
    POSTGRES_DB: kong
    POSTGRES_USER: kong
    POSTGRES_PASSWORD: ${KONG_DB_PASSWORD}
  volumes:
    - kong_db_data:/var/lib/postgresql/data

kong:
  image: kong:3.4.0-alpine
  environment:
    KONG_DATABASE: postgres
    KONG_PG_HOST: kong_db
    KONG_PG_USER: kong
    KONG_PG_PASSWORD: ${KONG_DB_PASSWORD}
    KONG_PROXY_ACCESS_LOG: /dev/stdout
    KONG_ADMIN_ACCESS_LOG: /dev/stdout
    KONG_PROXY_ERROR_LOG: /dev/stderr
    KONG_ADMIN_ERROR_LOG: /dev/stderr
    KONG_ADMIN_LISTEN: 0.0.0.0:8001
  ports:
    - "8000:8000"   # Proxy
    - "8443:8443"   # Proxy SSL
    - "8001:8001"   # Admin API
  networks:
    - bionex-network
  depends_on:
    - kong_db
  command: kong start
```

#### Kong Configuration (Admin API)

```bash
# Add service (Bionex API backend)
curl -X POST http://kong:8001/services \
  -d name="bionex-api" \
  -d url="http://api-backend:8000"

# Add route
curl -X POST http://kong:8001/services/bionex-api/routes \
  -d "hosts[]=api.bionex.local" \
  -d "protocols[]=https"

# Add JWT authentication plugin
curl -X POST http://kong:8001/services/bionex-api/plugins \
  -d name="jwt" \
  -d config.key_claim_name="sub" \
  -d config.secret_is_base64="false"

# Add rate limiting plugin
curl -X POST http://kong:8001/services/bionex-api/plugins \
  -d name="rate-limiting" \
  -d config.minute=1000 \
  -d config.hour=10000 \
  -d config.policy="redis" \
  -d config.redis_host="redis" \
  -d config.redis_port=6379

# Add request/response logging plugin
curl -X POST http://kong:8001/services/bionex-api/plugins \
  -d name="request-transformer" \
  -d config.add.headers="X-Request-ID:%{http.request.headers.x-request-id}"
```

#### Kong Lua Plugin (Custom Business Logic)

```lua
-- plugins/bionex-auth/handler.lua
local plugin = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

function plugin:header_filter(conf)
  -- Add security headers to response
  ngx.header["X-Content-Type-Options"] = "nosniff"
  ngx.header["X-Frame-Options"] = "DENY"
  ngx.header["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
end

function plugin:body_filter(conf)
  -- Sanitize response for PII
  if ngx.var.response_code == 200 then
    local response = ngx.arg[1]
    -- Remove sensitive fields before returning to client
  end
end

return plugin
```

---

### 7. Prometheus + Grafana (Monitoring)

**Why Prometheus?**
- Time-series database (store metrics with timestamps)
- PromQL query language
- Pulls metrics from exporters (vs push)
- Grafana integration for dashboards
- AlertManager for alerting

#### Configuration

```yaml
# docker-compose.yml
prometheus:
  image: prom/prometheus:latest
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
    - prometheus_data:/prometheus
  command:
    - '--config.file=/etc/prometheus/prometheus.yml'
    - '--storage.tsdb.path=/prometheus'
    - '--storage.tsdb.retention.time=90d'
  ports:
    - "9090:9090"
  networks:
    - bionex-network

grafana:
  image: grafana/grafana:latest
  environment:
    GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD}
    GF_USERS_ALLOW_SIGN_UP: "false"
  volumes:
    - grafana_data:/var/lib/grafana
    - ./grafana_dashboards:/etc/grafana/provisioning/dashboards
    - ./grafana_datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml
  ports:
    - "3000:3000"
  networks:
    - bionex-network
  depends_on:
    - prometheus
```

#### prometheus.yml

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # FastAPI metrics
  - job_name: 'fastapi'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'

  # PostgreSQL metrics
  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']  # postgres_exporter

  # Redis metrics
  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']  # redis_exporter

  # RabbitMQ metrics
  - job_name: 'rabbitmq'
    static_configs:
      - targets: ['localhost:15692']

  # Docker metrics
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['localhost:8080']

rule_files:
  - /etc/prometheus/alert_rules.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

#### FastAPI Prometheus Integration

```python
# app/main.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import time

# Define metrics
request_count = Counter(
    'bionex_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'bionex_http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

active_requests = Gauge(
    'bionex_http_requests_in_progress',
    'Active HTTP requests'
)

@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    method = request.method
    endpoint = request.url.path
    
    active_requests.inc()
    start = time.time()
    
    try:
        response = await call_next(request)
        duration = time.time() - start
        
        request_count.labels(
            method=method,
            endpoint=endpoint,
            status=response.status_code
        ).inc()
        
        request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        return response
    finally:
        active_requests.dec()

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

#### Alert Rules

```yaml
# alert_rules.yml
groups:
  - name: bionex_alerts
    interval: 1m
    rules:
      # High Error Rate
      - alert: HighErrorRate
        expr: |
          (sum(rate(bionex_http_requests_total{status=~"5.."}[5m])) /
           sum(rate(bionex_http_requests_total[5m]))) > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected"
          description: "Error rate is above 5%"

      # Database Connection Pool Exhaustion
      - alert: DbPoolExhausted
        expr: |
          pg_stat_activity_current / pg_settings_max_connections > 0.8
        for: 5m
        annotations:
          summary: "Database pool near capacity"

      # Redis Memory High
      - alert: RedisMemoryHigh
        expr: |
          redis_memory_used_bytes / redis_memory_max_bytes > 0.9
        for: 5m
        annotations:
          summary: "Redis memory usage critical"

      # Message Queue Backlog
      - alert: RabbitMQQueueBacklog
        expr: |
          rabbitmq_queue_messages_total > 10000
        for: 10m
        annotations:
          summary: "RabbitMQ queue backlog growing"
```

---

### 8. ELK Stack (Log Aggregation)

**Why ELK?**
- Centralized logging for all services
- Full-text search (find audit entries)
- Compliance required for healthcare (7-year retention)
- HIPAA/GDPR evidence logging

#### Configuration

```yaml
# docker-compose.yml - Full ELK
elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:8.7.0
  environment:
    - discovery.type=single-node
    - xpack.security.enabled=true
    - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
  volumes:
    - elasticsearch_data:/usr/share/elasticsearch/data
  ports:
    - "9200:9200"
  networks:
    - bionex-network

logstash:
  image: docker.elastic.co/logstash/logstash:8.7.0
  volumes:
    - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
  environment:
    - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
    - ELASTICSEARCH_USERNAME=elastic
    - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
  ports:
    - "5000:5000/udp"
  depends_on:
    - elasticsearch
  networks:
    - bionex-network

kibana:
  image: docker.elastic.co/kibana/kibana:8.7.0
  environment:
    - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
    - ELASTICSEARCH_USERNAME=elastic
    - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
    - xpack.security.enabled=true
  ports:
    - "5601:5601"
  depends_on:
    - elasticsearch
  networks:
    - bionex-network
```

#### Logstash Configuration

```conf
# logstash.conf
input {
  # FastAPI logs via syslog
  udp {
    port => 5000
    type => "fastapi"
  }
  
  # File input (for batch imports)
  file {
    path => "/var/log/bionex/*.log"
    type => "bionex"
  }
}

filter {
  # Parse JSON logs
  if [type] == "fastapi" {
    json {
      source => "message"
    }
  }
  
  # Extract request ID for tracing
  grok {
    match => { "message" => "%{DATA:request_id}" }
  }
  
  # Add geo-location for IP addresses
  geoip {
    source => "ip_address"
  }
}

output {
  # Send to Elasticsearch
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    user => "elastic"
    password => "${ELASTICSEARCH_PASSWORD}"
    index => "bionex-%{+YYYY.MM.dd}"
  }
  
  # Also output to stdout for debugging
  stdout {
    codec => rubydebug
  }
}
```

#### Python Logging Configuration

```python
# app/logging_config.py
import logging
import json
from pythonjsonlogger import jsonlogger

class BionexJSONFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = datetime.utcnow().isoformat()
        log_record['service'] = 'bionex-api'
        log_record['version'] = '1.0.0'
        
        # Add request context if available
        if hasattr(record, 'request_id'):
            log_record['request_id'] = record.request_id
        if hasattr(record, 'user_id'):
            log_record['user_id'] = record.user_id

# Configure logging
logging.basicConfig(
    format='%(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler()  # stdout to Docker
    ]
)

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = BionexJSONFormatter()
handler.setFormatter(formatter)
logger.addHandler(handler)
```

---

## Data Flow Architecture

### Complete Request Flow

```
1. Client sends request:
   POST /api/v1/records/encrypted
   HEAD: Authorization: Bearer {jwt_token}
   HEAD: X-Sharing-Token: {sharing_token}
   HEAD: X-Session-Key-Hash: {key_hash}

2. Request hits Nginx (SSL termination):
   ├─ TLS 1.3 handshake
   ├─ Verify certificate
   └─ Pass to Kong

3. Kong API Gateway:
   ├─ Extract JWT from Authorization header
   ├─ Verify JWT signature using Kong JWT plugin
   ├─ Check rate limits (Redis lookup): 0.1ms
   ├─ Add X-Request-ID header for tracing
   └─ Route to FastAPI backend pod

4. FastAPI Backend:
   ├─ Middleware validates sharing token
   ├─ Query session_keys table (DB): 15ms
   ├─ Compare request hash with DB hash
   │  ├─ If cache hit (Redis): 0.1ms
   │  └─ If cache miss: 15ms (stores in Redis)
   ├─ Check expiration (now() < expires_at)
   ├─ Query encrypted_record_vaults (DB): 15ms
   ├─ Return ciphertext + nonce + auth_tag: 1ms
   │  
   └─ Async: Queue audit log
       └─ Send to RabbitMQ: 1ms

5. Message Queue Processing (Async):
   ├─ RabbitMQ receives audit log message
   ├─ Route to audit_logs queue
   └─ Celery worker picks up task
       ├─ Sign audit log with ECDSA: 15ms
       ├─ Insert into DB: 10ms
       └─ Publish to Elasticsearch: 5ms

6. Logging & Monitoring:
   ├─ Request duration metric sent to Prometheus
   ├─ Logs sent to ELK Stack (async)
   ├─ Audit entry visible in Kibana after 5-10s
   └─ Grafana dashboard updated

Total Server Response Time: 18-19ms ✅
Total With Async Operations: 35-40ms
```

---

## Deployment Architecture

### Kubernetes Setup (Recommended for Production)

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bionex-api
spec:
  replicas: 3  # 3 API pods for HA
  selector:
    matchLabels:
      app: bionex-api
  template:
    metadata:
      labels:
        app: bionex-api
    spec:
      containers:
      - name: api
        image: bionex-api:1.0.0
        ports:
        - containerPort: 8000
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: bionex-secrets
              key: database-url
        - name: VAULT_ADDR
          value: "https://vault.bionex.local:8200"
        - name: VAULT_TOKEN
          valueFrom:
            secretKeyRef:
              name: bionex-secrets
              key: vault-token
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: bionex-api-service
spec:
  selector:
    app: bionex-api
  type: LoadBalancer
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8000

---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: celery-worker
spec:
  serviceName: celery-workers
  replicas: 5
  selector:
    matchLabels:
      app: celery-worker
  template:
    metadata:
      labels:
        app: celery-worker
    spec:
      containers:
      - name: worker
        image: bionex-api:1.0.0
        command: ["celery", "-A", "app.celery_app", "worker", "--loglevel=info"]
        env:
        - name: CELERY_BROKER_URL
          valueFrom:
            secretKeyRef:
              name: bionex-secrets
              key: rabbitmq-url
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
```

---

## Security & Compliance

### Encryption in Transit

```yaml
# Ingress configuration with TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bionex-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.bionex.local
    secretName: bionex-tls-cert
  rules:
  - host: api.bionex.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: bionex-api-service
            port:
              number: 443
```

### Network Policies

```yaml
# NetworkPolicy to restrict inter-pod communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bionex-network-policy
spec:
  podSelector:
    matchLabels:
      app: bionex-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - podSelector:
        matchLabels:
          app: kong
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
    - protocol: TCP
      port: 6379  # Redis
    - protocol: TCP
      port: 5672  # RabbitMQ
```

---

## Monitoring & Observability

### Key Metrics to Track

```
Request-Level Metrics:
├─ Request rate (req/sec)
├─ Response time (ms)
├─ Error rate (%)
├─ Cache hit rate (%)
└─ Database query time (ms)

System-Level Metrics:
├─ CPU usage per pod
├─ Memory usage per pod
├─ Disk I/O (IOPS)
├─ Network I/O (bytes)
└─ Database connections

Business-Level Metrics:
├─ Doctor access count per day
├─ Session keys rotated per day
├─ Audit logs created per day
├─ Failed signature verifications
└─ Data breach attempts detected
```

---

## Disaster Recovery & Backup

### RTO/RPO Targets

```
RTO (Recovery Time Objective):
├─ API Service: < 5 minutes
├─ Database: < 15 minutes
└─ Cache: < 1 minute

RPO (Recovery Point Objective):
├─ Database: < 1 hour
├─ Audit Logs: < 5 minutes (replicated in real-time)
└─ Config: < 1 day
```

### Backup Strategy

```bash
#!/bin/bash
# Daily automated backups

# PostgreSQL backup to S3
aws s3 cp s3://bionex-backups/postgresql/latest.dump.gpg \
  /local/backup/latest.dump.gpg

# MongoDB backup (audit logs)
mongodump --uri="mongodb://..." --archive=/local/backup/mongo.archive

# Encrypt and upload to multiple regions
for region in us-east-1 eu-west-1 ap-southeast-1; do
  aws s3 cp /local/backup/latest.dump.gpg \
    s3://bionex-backups-${region}/postgresql/$(date +%Y%m%d).dump.gpg \
    --region $region
done

# Test restore quarterly
```

---

## Cost Analysis

### AWS Cost Estimate (Monthly)

```
Infrastructure:
├─ RDS PostgreSQL (Multi-AZ): $500
├─ ElastiCache Redis (Cluster): $300
├─ EC2 Instances (3x t3.medium): $200
├─ RabbitMQ (Managed): $200
├─ Load Balancer: $20
├─ Data Transfer: $100
└─ Subtotal: $1,320/month

Managed Services:
├─ HashiCorp Vault Cloud: $200
├─ Monitoring (DataDog): $400
├─ Elasticsearch (Managed): $300
└─ Subtotal: $900/month

Development:
├─ GitHub Enterprise: $50
├─ CI/CD (GitLab): $100
└─ Subtotal: $150/month

Total: ~$2,370/month (~$28,440/year)

Per-User Cost (1000 active doctors):
├─ Infrastructure: $1.32/month
├─ Services: $0.90/month
└─ Total: $2.22/month per doctor
```

### Cost Optimization

```
1. Reserved Instances (30% savings): -$360/month
2. Spot Instances for workers: -$150/month
3. Data transfer optimization: -$30/month
4. Auto-scaling (down during off-hours): -$100/month

Total Optimized: ~$1,730/month
```

---

## Implementation Timeline

### Full Enterprise Deployment: 12-16 Weeks

```
Week 1-2: Infrastructure Setup
├─ Provision AWS/Azure/On-premise servers
├─ Setup PostgreSQL (primary + replica)
├─ Setup Redis (Sentinel)
└─ Setup RabbitMQ (cluster)

Week 3-4: API Gateway & Load Balancer
├─ Install Kong API Gateway
├─ Configure SSL/TLS
├─ Setup rate limiting
└─ Test authentication

Week 5-6: Vault & Secrets Management
├─ Setup HashiCorp Vault
├─ Migrate secrets from env vars
├─ Setup key rotation
└─ Audit secret access

Week 7-8: Monitoring & Logging
├─ Deploy Prometheus + Grafana
├─ Setup ELK Stack
├─ Create alert rules
└─ Create dashboards

Week 9-10: Phase 1 Implementation (Crypto)
├─ Implement ECDH key generation
├─ Implement ChaCha20-Poly1305
├─ Implement HKDF + ECDSA
└─ Unit tests (100% coverage)

Week 11-12: Phase 2 Implementation (Database & APIs)
├─ Database migrations
├─ Implement core API endpoints
├─ Implement session key management
└─ Integration tests

Week 13-14: Phase 3 Implementation (Sharing)
├─ Implement sharing workflows
├─ Implement revocation logic
├─ Implement rotation job
└─ End-to-end tests

Week 15-16: Load Testing & Deployment
├─ Load test (1000+ concurrent users)
├─ Performance tuning
├─ Security audit
└─ Go-live
```

---

## Environment-Specific Configurations

### Development Environment

```yaml
# docker-compose-dev.yml (Local development)
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: dev_password
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    ports:
      - "5672:5672"
      - "15672:15672"

  api:
    build: .
    environment:
      ENVIRONMENT: development
      DEBUG: "true"
      DATABASE_URL: "postgresql://postgres:dev_password@postgres:5432/bionex"
      REDIS_URL: "redis://redis:6379"
      RABBITMQ_URL: "amqp://guest:guest@rabbitmq:5672/"
    ports:
      - "8000:8000"
    volumes:
      - .:/app
    command: uvicorn app.main:app --reload --host 0.0.0.0
```

### Staging Environment

```yaml
# Kubernetes staging config
apiVersion: v1
kind: Namespace
metadata:
  name: bionex-staging
---
# All services deployed identically to production
# but with different data (test patients)
# Single replica for cost savings
```

### Production Environment

```yaml
# All HA setups
# Multi-region disaster recovery
# Full monitoring + alerting
# Encrypted backups
# 99.99% SLA target
```

---

**Document Complete**

This enterprise architecture provides:
- ✅ High availability (99.99% uptime target)
- ✅ Disaster recovery (RTO/RPO defined)
- ✅ Compliance (GDPR, HIPAA, NHS standards)
- ✅ Performance (18-40ms response times)
- ✅ Scalability (horizontal scaling ready)
- ✅ Security (encrypted at rest + in transit)
- ✅ Monitoring (all metrics tracked)
- ✅ Cost-optimized ($28k-$35k annually)
