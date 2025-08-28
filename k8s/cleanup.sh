#!/bin/bash

# Cleanup script for Auth-Sys Kubernetes deployment

echo "🗑️ Cleaning up Auth-Sys Kubernetes deployment..."

# Delete all resources
echo "Deleting all Kubernetes resources..."
kubectl delete -f ingress.yaml
kubectl delete -f frontend-service.yaml
kubectl delete -f frontend-deployment.yaml
kubectl delete -f frontend-configmap.yaml
kubectl delete -f backend-service.yaml
kubectl delete -f backend-deployment.yaml
kubectl delete -f backend-configmap.yaml
kubectl delete -f backend-secret.yaml
kubectl delete -f mysql-service.yaml
kubectl delete -f mysql-deployment.yaml
kubectl delete -f mysql-pvc.yaml
kubectl delete -f mysql-pv.yaml
kubectl delete -f mysql-configmap.yaml
kubectl delete -f mysql-secret.yaml

# Optional: Delete namespace if created
# kubectl delete namespace auth-sys

echo "✅ Cleanup completed!"
echo ""
echo "To stop Minikube completely:"
echo "minikube stop"
echo "minikube delete"
