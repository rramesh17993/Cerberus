# SecureScan Framework Deployment Guide

This guide covers deployment options for the SecureScan Framework across different environments.

## Quick Start

### Docker Compose (Recommended)
```bash
# Clone repository
git clone https://github.com/securescan-framework/securescan-framework.git
cd securescan-framework

# Copy environment configuration
cp .env.example .env

# Edit configuration
nano .env

# Start services
docker-compose up -d

# Check status
docker-compose ps
```

### Local Development
```bash
# Backend (FastAPI)
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend (React)
cd frontend
npm install
npm run dev

# CLI
cd cli
npm install
npm run build
npm link
```

## Deployment Options

### 1. Production Docker Deployment

#### Docker Compose Production
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/ssl/certs
    depends_on:
      - api
      - frontend

  api:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    environment:
      - DATABASE_URL=postgresql://user:password@db:5432/securescan
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - db
      - redis

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.prod
    environment:
      - REACT_APP_API_URL=${API_URL}

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: securescan
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

#### Environment Configuration
```bash
# .env.prod
DATABASE_URL=postgresql://securescan:${DB_PASSWORD}@localhost:5432/securescan
REDIS_URL=redis://localhost:6379
JWT_SECRET=${JWT_SECRET}
API_URL=https://api.securescan.example.com
FRONTEND_URL=https://securescan.example.com
CORS_ORIGINS=["https://securescan.example.com"]

# Security
JWT_EXPIRATION_HOURS=24
API_RATE_LIMIT=1000
ENABLE_HTTPS=true
SSL_CERT_PATH=/etc/ssl/certs/cert.pem
SSL_KEY_PATH=/etc/ssl/private/key.pem

# Monitoring
ENABLE_METRICS=true
SENTRY_DSN=${SENTRY_DSN}
LOG_LEVEL=info
```

### 2. Kubernetes Deployment

#### Namespace
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: securescan
  labels:
    name: securescan
```

#### ConfigMap
```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: securescan-config
  namespace: securescan
data:
  DATABASE_URL: "postgresql://securescan:password@postgres:5432/securescan"
  REDIS_URL: "redis://redis:6379"
  API_URL: "https://api.securescan.example.com"
  FRONTEND_URL: "https://securescan.example.com"
  LOG_LEVEL: "info"
```

#### Secrets
```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: securescan-secrets
  namespace: securescan
type: Opaque
data:
  JWT_SECRET: <base64-encoded-secret>
  DB_PASSWORD: <base64-encoded-password>
  SENTRY_DSN: <base64-encoded-dsn>
```

#### Database Deployment
```yaml
# k8s/postgres.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: securescan
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_DB
          value: securescan
        - name: POSTGRES_USER
          value: securescan
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: securescan-secrets
              key: DB_PASSWORD
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: securescan
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: securescan
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
```

#### API Deployment
```yaml
# k8s/api.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: securescan
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: securescan/api:latest
        envFrom:
        - configMapRef:
            name: securescan-config
        - secretRef:
            name: securescan-secrets
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: securescan
spec:
  selector:
    app: api
  ports:
  - port: 8000
    targetPort: 8000
```

#### Frontend Deployment
```yaml
# k8s/frontend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: securescan
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        image: securescan/frontend:latest
        envFrom:
        - configMapRef:
            name: securescan-config
        ports:
        - containerPort: 3000
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: securescan
spec:
  selector:
    app: frontend
  ports:
  - port: 3000
    targetPort: 3000
```

#### Ingress
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: securescan-ingress
  namespace: securescan
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - securescan.example.com
    - api.securescan.example.com
    secretName: securescan-tls
  rules:
  - host: securescan.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 3000
  - host: api.securescan.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 8000
```

### 3. Cloud Deployments

#### AWS EKS
```bash
# Create EKS cluster
eksctl create cluster --name securescan --region us-west-2 --nodegroup-name workers --node-type t3.medium --nodes 3

# Apply manifests
kubectl apply -f k8s/

# Setup load balancer
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/aws/deploy.yaml
```

#### Google GKE
```bash
# Create GKE cluster
gcloud container clusters create securescan --zone us-central1-a --num-nodes 3

# Apply manifests
kubectl apply -f k8s/

# Setup ingress
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/cloud/deploy.yaml
```

#### Azure AKS
```bash
# Create AKS cluster
az aks create --resource-group securescan-rg --name securescan --node-count 3 --enable-addons monitoring

# Apply manifests
kubectl apply -f k8s/
```

### 4. Cloud-Native Services

#### AWS
```yaml
# cloudformation/securescan.yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  # RDS PostgreSQL
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      EngineVersion: '15.4'
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      DBName: securescan
      MasterUsername: securescan
      MasterUserPassword: !Ref DBPassword

  # ElastiCache Redis
  Redis:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      CacheNodeType: cache.t3.micro
      Engine: redis
      NumCacheNodes: 1

  # ECS Fargate
  ECSCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: securescan
```

#### Google Cloud
```yaml
# terraform/gcp.tf
resource "google_sql_database_instance" "main" {
  name             = "securescan-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
  }
}

resource "google_cloud_run_service" "api" {
  name     = "securescan-api"
  location = "us-central1"

  template {
    spec {
      containers {
        image = "gcr.io/project/securescan-api"
      }
    }
  }
}
```

## SSL/TLS Configuration

### Let's Encrypt with Certbot
```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificates
sudo certbot --nginx -d securescan.example.com -d api.securescan.example.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Custom SSL Certificates
```nginx
# nginx/ssl.conf
server {
    listen 443 ssl http2;
    server_name securescan.example.com;

    ssl_certificate /etc/ssl/certs/securescan.crt;
    ssl_certificate_key /etc/ssl/private/securescan.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    location / {
        proxy_pass http://frontend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring and Observability

### Prometheus Configuration
```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'securescan-api'
    static_configs:
      - targets: ['api:8000']
    metrics_path: /metrics

  - job_name: 'securescan-frontend'
    static_configs:
      - targets: ['frontend:3000']
    metrics_path: /metrics
```

### Grafana Dashboards
```json
{
  "dashboard": {
    "title": "SecureScan Metrics",
    "panels": [
      {
        "title": "API Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
          }
        ]
      }
    ]
  }
}
```

## Backup and Recovery

### Database Backup
```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
DB_NAME="securescan"

# Create backup
pg_dump -h localhost -U securescan -d $DB_NAME > $BACKUP_DIR/securescan_$DATE.sql

# Compress
gzip $BACKUP_DIR/securescan_$DATE.sql

# Cleanup old backups (keep 7 days)
find $BACKUP_DIR -name "securescan_*.sql.gz" -mtime +7 -delete
```

### Volume Backup
```bash
#!/bin/bash
# volume-backup.sh
docker run --rm -v securescan_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz /data
```

## Security Hardening

### Container Security
```dockerfile
# Use non-root user
RUN addgroup -g 1001 -S securescan && \
    adduser -S securescan -u 1001 -G securescan

USER securescan

# Read-only filesystem
FROM alpine:latest
RUN adduser -D -s /bin/sh securescan
USER securescan
COPY --chown=securescan:securescan app /app
WORKDIR /app
```

### Network Policies
```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: securescan-network-policy
  namespace: securescan
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

## Performance Optimization

### Database Optimization
```sql
-- PostgreSQL optimization
CREATE INDEX CONCURRENTLY idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX CONCURRENTLY idx_scans_created_at ON scans(created_at);
CREATE INDEX CONCURRENTLY idx_projects_user_id ON projects(user_id);

-- Connection pooling
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
```

### Redis Configuration
```conf
# redis.conf
maxmemory 256mb
maxmemory-policy allkeys-lru
tcp-keepalive 60
timeout 0
```

### Load Balancing
```nginx
# nginx/load-balancer.conf
upstream api_backend {
    server api-1:8000;
    server api-2:8000;
    server api-3:8000;
}

server {
    location /api/ {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Issues
```bash
# Check database connectivity
docker exec -it securescan-db psql -U securescan -d securescan -c "SELECT 1;"

# Check logs
docker logs securescan-api
```

#### 2. Scanner Container Issues
```bash
# Check Docker daemon
docker info

# Pull scanner images
docker pull semgrep/semgrep:latest
docker pull aquasec/trivy:latest
```

#### 3. Memory Issues
```bash
# Check memory usage
docker stats

# Increase memory limits in docker-compose
services:
  api:
    mem_limit: 1g
```

### Health Checks
```yaml
# docker-compose health checks
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

## Scaling

### Horizontal Scaling
```yaml
# docker-compose.scale.yml
services:
  api:
    deploy:
      replicas: 3
    depends_on:
      - db
      - redis

  worker:
    deploy:
      replicas: 5
    depends_on:
      - redis
```

### Auto-scaling (Kubernetes)
```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-hpa
  namespace: securescan
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```