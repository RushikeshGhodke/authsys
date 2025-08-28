#!/bin/bash

# Auth-Sys Kubernetes Deployment Script for Minikube
# This script deploys the entire auth-sys application to Minikube

echo "🚀 Starting Auth-Sys Kubernetes Deployment..."

# Step 1: Start Minikube (if not already running)
echo "📋 Step 1: Starting Minikube..."
minikube start --driver=docker --memory=4096 --cpus=2

# Step 2: Enable required addons
echo "📋 Step 2: Enabling required Minikube addons..."
minikube addons enable ingress
minikube addons enable storage-provisioner
minikube addons enable default-storageclass

# Step 3: Set Docker environment to use Minikube's Docker daemon
echo "📋 Step 3: Setting up Docker environment for Minikube..."
eval $(minikube docker-env)

# Step 4: Build Docker images in Minikube's Docker environment
echo "📋 Step 4: Building Docker images..."
echo "Building backend image..."
cd ../backend
docker build -t rushikeshghodke/auth-sys-backend:latest .

echo "Building frontend image..."
cd ../frontend
docker build -t rushikeshghodke/auth-sys-frontend:latest .

cd ../k8s

# Step 5: Create namespace (optional but recommended)
echo "📋 Step 5: Creating namespace..."
kubectl create namespace auth-sys || echo "Namespace already exists"

# Step 6: Deploy MySQL components
echo "📋 Step 6: Deploying MySQL components..."
kubectl apply -f mysql-secret.yaml
kubectl apply -f mysql-configmap.yaml
kubectl apply -f mysql-pv.yaml
kubectl apply -f mysql-pvc.yaml
kubectl apply -f mysql-deployment.yaml
kubectl apply -f mysql-service.yaml

# Step 7: Wait for MySQL to be ready
echo "📋 Step 7: Waiting for MySQL to be ready..."
kubectl wait --for=condition=ready pod -l app=mysql --timeout=300s

# Step 8: Deploy Backend components
echo "📋 Step 8: Deploying Backend components..."
kubectl apply -f backend-secret.yaml
kubectl apply -f backend-configmap.yaml
kubectl apply -f backend-deployment.yaml
kubectl apply -f backend-service.yaml

# Step 9: Wait for Backend to be ready
echo "📋 Step 9: Waiting for Backend to be ready..."
kubectl wait --for=condition=ready pod -l app=backend --timeout=300s

# Step 10: Deploy Frontend components
echo "📋 Step 10: Deploying Frontend components..."
kubectl apply -f frontend-configmap.yaml
kubectl apply -f frontend-deployment.yaml
kubectl apply -f frontend-service.yaml

# Step 11: Wait for Frontend to be ready
echo "📋 Step 11: Waiting for Frontend to be ready..."
kubectl wait --for=condition=ready pod -l app=frontend --timeout=300s

# Step 12: Deploy Ingress
echo "📋 Step 12: Deploying Ingress..."
kubectl apply -f ingress.yaml

# Step 13: Wait for Ingress to get an IP
echo "📋 Step 13: Waiting for Ingress to be ready..."
sleep 30

# Step 14: Get Minikube IP and update hosts file
echo "📋 Step 14: Setting up local DNS..."
MINIKUBE_IP=$(minikube ip)
echo "Minikube IP: $MINIKUBE_IP"

# Check if running on Windows (Git Bash) or Linux/Mac
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Windows (Git Bash)
    echo "🪟 Detected Windows environment"
    echo "Please manually add the following line to your hosts file:"
    echo "File location: C:\\Windows\\System32\\drivers\\etc\\hosts"
    echo "$MINIKUBE_IP auth-sys.local"
    echo ""
    echo "Or run this command as Administrator in Command Prompt:"
    echo "echo $MINIKUBE_IP auth-sys.local >> C:\\Windows\\System32\\drivers\\etc\\hosts"
else
    # Linux/Mac
    echo "🐧 Detected Unix-like environment"
    echo "Adding entry to /etc/hosts (requires sudo)..."
    sudo sh -c "echo '$MINIKUBE_IP auth-sys.local' >> /etc/hosts"
fi

# Step 15: Display deployment status
echo "📋 Step 15: Checking deployment status..."
echo ""
echo "🔍 Deployment Status:"
kubectl get pods -o wide
echo ""
echo "🔍 Services:"
kubectl get services
echo ""
echo "🔍 Ingress:"
kubectl get ingress
echo ""

# Step 16: Display access information
echo "✅ Deployment completed successfully!"
echo ""
echo "🌐 Access your application:"
echo "Frontend: http://auth-sys.local"
echo "Backend API: http://auth-sys.local/api"
echo "Health Check: http://auth-sys.local/api/health"
echo ""
echo "📊 Useful commands:"
echo "View logs - Backend: kubectl logs -l app=backend"
echo "View logs - Frontend: kubectl logs -l app=frontend"
echo "View logs - MySQL: kubectl logs -l app=mysql"
echo "Port forward (alternative access):"
echo "  Frontend: kubectl port-forward service/frontend-service 8080:80"
echo "  Backend: kubectl port-forward service/backend-service 3000:3000"
echo ""
echo "🗑️ To cleanup:"
echo "kubectl delete -f ."
echo "minikube stop"

# Optional: Open Minikube dashboard
echo ""
read -p "🎛️ Do you want to open Minikube dashboard? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    minikube dashboard
fi
