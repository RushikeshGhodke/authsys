#!/bin/bash

# Monitoring script for Auth-Sys Kubernetes deployment

echo "📊 Auth-Sys Kubernetes Monitoring Dashboard"
echo "=========================================="

while true; do
    clear
    echo "📊 Auth-Sys Kubernetes Monitoring Dashboard"
    echo "=========================================="
    echo "⏰ $(date)"
    echo ""
    
    echo "🔍 Pod Status:"
    kubectl get pods -o wide
    echo ""
    
    echo "🔍 Service Status:"
    kubectl get services
    echo ""
    
    echo "🔍 Ingress Status:"
    kubectl get ingress
    echo ""
    
    echo "💾 Resource Usage:"
    kubectl top pods 2>/dev/null || echo "Metrics server not available"
    echo ""
    
    echo "🔗 Access URLs:"
    MINIKUBE_IP=$(minikube ip)
    echo "Frontend: http://auth-sys.local (or http://$MINIKUBE_IP)"
    echo "Backend API: http://auth-sys.local/api (or http://$MINIKUBE_IP/api)"
    echo ""
    
    echo "Press Ctrl+C to exit monitoring..."
    sleep 10
done
