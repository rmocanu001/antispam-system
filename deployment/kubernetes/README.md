# Migrare de la Docker Compose la Kubernetes

## Cerinte

- Cluster Kubernetes (minikube, k3s, sau kubeadm)
- `kubectl` configurat
- Container registry accesibil din cluster (local registry sau Docker Hub)
- Ingress controller instalat (nginx-ingress recomandat)

## Pasul 1: Build si Push imagini

```bash
# Build imaginile custom
docker build -t antispam:latest .
docker build -t antispam-postfix:latest -f deployment/postfix/Dockerfile deployment/postfix/
docker build -t antispam-dovecot:latest -f deployment/dovecot/Dockerfile deployment/dovecot/
docker build -t antispam-spamassassin:latest -f deployment/spamassassin/Dockerfile deployment/spamassassin/

# Pentru minikube (load direct in cluster):
minikube image load antispam:latest
minikube image load antispam-postfix:latest
minikube image load antispam-dovecot:latest
minikube image load antispam-spamassassin:latest

# Pentru cluster remote (push la registry):
# docker tag antispam:latest registry.igsu.local/antispam:latest
# docker push registry.igsu.local/antispam:latest
# (similar pentru celelalte imagini)
```

## Pasul 2: Deploy in ordine

```bash
# 1. Namespace
kubectl apply -f deployment/kubernetes/namespace.yaml

# 2. ConfigMaps si PVCs
kubectl apply -f deployment/kubernetes/configmaps.yaml
kubectl apply -f deployment/kubernetes/pvcs.yaml

# 3. Servicii de baza (fara dependente)
kubectl apply -f deployment/kubernetes/ollama-statefulset.yaml
kubectl apply -f deployment/kubernetes/clamav-daemonset.yaml
kubectl apply -f deployment/kubernetes/spamassassin-daemonset.yaml

# 4. Asteapta ca Ollama sa fie ready si modelul descarcat
kubectl -n antispam-system wait --for=condition=ready pod -l app=ollama --timeout=300s

# 5. Servicii de mail
kubectl apply -f deployment/kubernetes/dovecot-statefulset.yaml
kubectl apply -f deployment/kubernetes/postfix-deployment.yaml

# 6. Policy service si webmail
kubectl apply -f deployment/kubernetes/antispam-deployment.yaml
kubectl apply -f deployment/kubernetes/roundcube-deployment.yaml

# 7. Autoscaling
kubectl apply -f deployment/kubernetes/hpa.yaml
```

Sau deploy totul dintr-o data:
```bash
kubectl apply -f deployment/kubernetes/
```

## Pasul 3: Verificare

```bash
# Verifica starea pod-urilor
kubectl -n antispam-system get pods

# Verifica serviciile
kubectl -n antispam-system get svc

# Verifica modelul Ollama
kubectl -n antispam-system exec -it statefulset/ollama -- ollama list

# Verifica log-uri Postfix
kubectl -n antispam-system logs deployment/postfix

# Test email (din interiorul cluster-ului)
kubectl -n antispam-system run test-smtp --rm -it --image=alpine -- sh -c \
  "apk add --no-cache swaks && swaks --to user1@igsu.local --from test@example.com --server postfix-svc:25"
```

## Pasul 4: Acces Roundcube

```bash
# Port-forward pentru acces local
kubectl -n antispam-system port-forward svc/roundcube-svc 8080:8080

# Sau foloseste Ingress (necesita nginx-ingress + DNS pt webmail.igsu.local)
# Login: user1@igsu.local / test123
```

## Arhitectura Kubernetes

```
                                    ┌─────────────────────────────────────────┐
                                    │         namespace: antispam-system       │
                                    │                                          │
  Internet ──► LoadBalancer ──►     │  ┌──────────┐      ┌───────────────┐    │
               (port 25/587)        │  │ Postfix  │──SA──│ SpamAssassin  │    │
                                    │  │ Deploy   │      │ DaemonSet     │    │
                                    │  │ (HPA 2-10│      └───────────────┘    │
                                    │  └────┬─────┘                           │
                                    │       │ policy     ┌───────────────┐    │
                                    │       ├───────────►│ Antispam Go   │    │
                                    │       │            │ Deploy (HPA)  │    │
                                    │       │ LMTP       └───────┬───────┘    │
                                    │       ▼                    │            │
                                    │  ┌──────────┐         ┌───▼───┐        │
                                    │  │ Dovecot  │         │Ollama │        │
                                    │  │ Stateful │         │Stateful│       │
                                    │  │ Set (PVC)│         │Set(PVC)│       │
                                    │  └────┬─────┘         └───────┘        │
                                    │       │ IMAP                            │
                                    │  ┌────▼─────┐      ┌───────────────┐    │
                                    │  │Roundcube │      │   ClamAV      │    │
                                    │  │ Deploy   │      │  DaemonSet    │    │
                                    │  └──────────┘      └───────────────┘    │
                                    │       ▲ Ingress                         │
                                    └───────┼─────────────────────────────────┘
                                            │
                              webmail.igsu.local:8080
```

## Scalabilitate

### Horizontal Pod Autoscaler (HPA)
- **Postfix**: 2-10 replicas, scala la 70% CPU
- **Antispam Policy**: 1-5 replicas, scala la 80% CPU
- SpamAssassin si ClamAV ruleaza ca DaemonSet (un pod pe fiecare nod)

### Adaugare noduri
```bash
# Adauga nod nou la cluster
kubeadm join <master-ip>:6443 --token <token>

# SpamAssassin si ClamAV se deployeaza automat pe noul nod (DaemonSet)
# Postfix si Antispam scala automat daca CPU depaseste threshold-ul
```

### Scalare manuala
```bash
# Scala Postfix la 5 replicas
kubectl -n antispam-system scale deployment postfix --replicas=5

# Scala Antispam Policy
kubectl -n antispam-system scale deployment antispam-policy --replicas=3
```

## Cerinte Hardware Recomandate

### Cluster de test (1 nod)
- CPU: 4 cores
- RAM: 16 GB
- Disk: 50 GB SSD

### Cluster de productie (3 noduri)
- **Nod control plane + Ollama**: 8 cores, 32 GB RAM, 100 GB NVMe
- **Nod worker 1**: 4 cores, 8 GB RAM, 50 GB SSD
- **Nod worker 2**: 4 cores, 8 GB RAM, 50 GB SSD

### Cu GPU (recomandat pentru Ollama)
- Ollama pe nod cu NVIDIA GPU (8 GB VRAM minim)
- Adauga `nvidia.com/gpu: 1` la resources.limits in ollama-statefulset.yaml
- Instaleaza NVIDIA device plugin: `kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/main/nvidia-device-plugin.yml`

## Diferente Docker Compose vs Kubernetes

| Aspect | Docker Compose | Kubernetes |
|--------|---------------|------------|
| Networking | Bridge network, DNS automat | ClusterIP Services, DNS via CoreDNS |
| Storage | Named volumes | PersistentVolumeClaims |
| Scaling | Manual (`--scale`) | HPA automat |
| Health checks | docker healthcheck | readiness/liveness probes |
| Config | .env file | ConfigMaps + Secrets |
| Load balancing | Nu | Service type LoadBalancer |
| Recovery | `restart: unless-stopped` | Pod restart policy + ReplicaSet |
| Rollback | Manual | `kubectl rollout undo` |
