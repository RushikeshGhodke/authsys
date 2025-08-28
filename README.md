# 🔐 Auth-Sys - Complete Authentication System

A full-stack authentication system built with modern technologies, featuring secure user management, JWT authentication, and cloud-ready deployment.

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-19+-blue.svg)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-blue.svg)](https://kubernetes.io/)

## 📋 Table of Contents

- [🏗️ Architecture](#️-architecture)
- [✨ Features](#-features)
- [🛠️ Tech Stack](#️-tech-stack)
- [🚀 Quick Start](#-quick-start)
- [💻 Development Setup](#-development-setup)
- [🐳 Docker Setup](#-docker-setup)
- [☸️ Kubernetes Setup](#️-kubernetes-setup)
- [📡 API Documentation](#-api-documentation)
- [🔧 Configuration](#-configuration)
- [🧪 Testing](#-testing)
- [🚀 Deployment](#-deployment)
- [🤝 Contributing](#-contributing)

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend      │    │    Database     │
│   (React)       │◄──►│   (Express)     │◄──►│    (MySQL)      │
│   Port: 5173    │    │   Port: 3000    │    │   Port: 3306    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Cloudinary    │
                    │ (File Storage)  │
                    └─────────────────┘
```

## ✨ Features

### 🔒 Authentication & Security
- **User Registration** with email validation
- **Secure Login** with username/email support
- **JWT Authentication** with access & refresh tokens
- **Password Management** (change, validation)
- **Avatar Upload** with Cloudinary integration
- **HTTP-only Cookies** for token storage
- **CORS Protection** with configurable origins

### 👤 User Management
- **Profile Management** (view, edit, update)
- **Avatar Upload & Update**
- **User Session Management**
- **Account Security Settings**
- **Responsive UI** with Tailwind CSS

### 🏗️ Architecture Features
- **RESTful API** design
- **Modular Backend** structure
- **React Context** for state management
- **Error Handling** middleware
- **Input Validation** & sanitization
- **Database Migrations** ready

### 🚀 DevOps Ready
- **Docker** containerization
- **Kubernetes** deployment manifests
- **Environment** configuration
- **Health Checks** & monitoring
- **Horizontal Scaling** support

## 🛠️ Tech Stack

### Frontend
- **React 19** - Frontend library
- **Vite** - Build tool & dev server
- **React Router** - Client-side routing
- **Tailwind CSS** - Utility-first CSS
- **Lucide React** - Icon library
- **Context API** - State management

### Backend
- **Node.js 18+** - Runtime environment
- **Express.js** - Web framework
- **MySQL** - Relational database
- **JWT** - Authentication tokens
- **bcryptjs** - Password hashing
- **Cloudinary** - Image storage
- **Multer** - File upload handling

### DevOps & Infrastructure
- **Docker** - Containerization
- **Kubernetes** - Orchestration
- **Nginx** - Web server (production)
- **MySQL** - Database with persistence

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- MySQL 8+
- npm or yarn
- Git

```bash
# Clone the repository
git clone https://github.com/RushikeshGhodke/authsys.git
cd auth-sys

# Install dependencies
npm run install:all

# Set up environment variables
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# Start development servers
npm run dev
```

## 💻 Development Setup

### 1. Clone & Install

```bash
# Clone repository
git clone https://github.com/RushikeshGhodke/authsys.git
cd auth-sys

# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install
```

### 2. Database Setup

```bash
# Create MySQL database
mysql -u root -p
CREATE DATABASE auth_sys;
USE auth_sys;

# Import schema
source backend/db/schema.sql;
```

### 3. Environment Configuration

**Backend (.env)**
```bash
# Server Configuration
NODE_ENV=development
PORT=3000
CORS_ORIGIN=http://localhost:5173

# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=auth_sys

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=1d

# Cloudinary Configuration (Optional)
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

**Frontend (.env)**
```bash
# API Configuration
VITE_API_URL=http://localhost:3000/api/v1
```

### 4. Start Development Servers

```bash
# Terminal 1 - Backend
cd backend
npm run dev

# Terminal 2 - Frontend
cd frontend
npm run dev
```

### 5. Access Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:3000/api/v1
- **Health Check**: http://localhost:3000/health

## 🐳 Docker Setup

### Local Docker Development

#### 1. Create Docker Network

```bash
# Create a custom network for container communication
docker network create auth-sys
```

#### 2. Build Docker Images

```bash
# Navigate to project root
cd auth-sys

# Build backend image
cd backend
docker build -t auth-sys-backend .

# Build frontend image
cd ../frontend
docker build -t auth-sys-frontend .
```

#### 3. Run Containers

**Step 1: Run MySQL Container**
```bash
docker run -d \
  --name mysql \
  --network auth-sys \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=auth_sys \
  mysql
```

**Step 2: Run Backend Container**
```bash
docker run -d \
  -p 3000:3000 \
  --network auth-sys \
  -e PORT=3000 \
  -e DB_HOST=mysql \
  -e DB_USER=root \
  -e DB_PASSWORD=root \
  -e DB_NAME=auth_sys \
  -e JWT_SECRET=secret \
  -e JWT_EXPIRES_IN=7d \
  -e CLOUDINARY_CLOUD_NAME=XYZ \
  -e CLOUDINARY_API_KEY=XYZ \
  -e CLOUDINARY_CLOUD_SECRET=XYZ \
  --name auth-sys-backend \
  auth-sys-backend
```

**Step 3: Run Frontend Container**
```bash
docker run -d \
  -p 80:80 \
  --network auth-sys \
  --name auth-sys-frontend \
  auth-sys-frontend
```

#### 4. Verify Deployment

```bash
# Check running containers
docker ps

# Check network
docker network ls
docker network inspect auth-sys

# View container logs
docker logs auth-sys-backend
docker logs auth-sys-frontend
docker logs mysql
```

#### 5. Access Application

- **Frontend**: http://localhost
- **Backend API**: http://localhost:3000/api/v1
- **Health Check**: http://localhost:3000/health

#### 6. Initialize Database (Optional)

If you need to import the schema manually:

```bash
# Copy schema file to MySQL container
docker cp backend/db/schema.sql mysql:/tmp/schema.sql

# Execute schema in MySQL
docker exec -it mysql mysql -u root -proot auth_sys -e "source /tmp/schema.sql"
```

#### 7. Useful Docker Commands

```bash
# View running containers
docker ps

# View all containers (including stopped)
docker ps -a

# View container logs
docker logs mysql
docker logs auth-sys-backend
docker logs auth-sys-frontend

# Follow logs in real-time
docker logs -f auth-sys-backend

# Execute commands in containers
docker exec -it mysql mysql -u root -proot
docker exec -it auth-sys-backend npm run test

# Stop containers
docker stop mysql auth-sys-backend auth-sys-frontend

# Remove containers
docker rm mysql auth-sys-backend auth-sys-frontend

# Remove network
docker network rm auth-sys

# Complete cleanup
docker stop mysql auth-sys-backend auth-sys-frontend
docker rm mysql auth-sys-backend auth-sys-frontend
docker network rm auth-sys
```

#### 8. One-line Setup Script

Create a setup script for easy deployment:

```bash
#!/bin/bash
# setup-docker.sh

echo "Creating Docker network..."
docker network create auth-sys

echo "Building images..."
cd backend && docker build -t auth-sys-backend .
cd ../frontend && docker build -t auth-sys-frontend .

echo "Starting MySQL..."
docker run -d --name mysql --network auth-sys \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=auth_sys \
  mysql

echo "Waiting for MySQL to start..."
sleep 30

echo "Starting Backend..."
docker run -d -p 3000:3000 --network auth-sys \
  -e PORT=3000 -e DB_HOST=mysql -e DB_USER=root \
  -e DB_PASSWORD=root -e DB_NAME=auth_sys \
  -e JWT_SECRET=secret -e JWT_EXPIRES_IN=7d \
  -e CLOUDINARY_CLOUD_NAME=XYZ \
  -e CLOUDINARY_API_KEY=XYZ \
  -e CLOUDINARY_CLOUD_SECRET=XYZ \
  --name auth-sys-backend auth-sys-backend

echo "Starting Frontend..."
docker run -d -p 80:80 --network auth-sys \
  --name auth-sys-frontend auth-sys-frontend

echo "Deployment complete!"
echo "Frontend: http://localhost"
echo "Backend: http://localhost:3000/api/v1"
```

Make it executable and run:
```bash
chmod +x setup-docker.sh
./setup-docker.sh
```

## ☸️ Kubernetes Setup

### Prerequisites
- Minikube or local Kubernetes cluster
- kubectl CLI tool
- Docker (for building images)

### 1. Start Minikube

```bash
# Start Minikube
minikube start --driver=docker

# Enable ingress addon
minikube addons enable ingress

# Check cluster status
kubectl cluster-info
```

### 2. Build & Push Images to Minikube

```bash
# Configure Docker to use Minikube's Docker daemon
eval $(minikube docker-env)

# Build images in Minikube
cd backend
docker build -t auth-sys-backend:latest .

cd ../frontend
docker build -t auth-sys-frontend:latest .
```

### 3. Deploy to Kubernetes

```bash
# Navigate to k8s directory
cd k8s

# Apply configurations in order
kubectl apply -f mysql-pv.yaml
kubectl apply -f mysql-pvc.yaml
kubectl apply -f mysql-secret.yaml
kubectl apply -f mysql-configmap.yaml
kubectl apply -f mysql-deployment.yaml
kubectl apply -f mysql-service.yaml

# Deploy backend
kubectl apply -f backend-secret.yaml
kubectl apply -f backend-configmap.yaml
kubectl apply -f backend-deployment.yaml
kubectl apply -f backend-service.yaml

# Deploy frontend
kubectl apply -f frontend-configmap.yaml
kubectl apply -f frontend-deployment.yaml
kubectl apply -f frontend-service.yaml

# Apply ingress
kubectl apply -f ingress.yaml
```

### 4. Verify Deployment

```bash
# Check all pods
kubectl get pods

# Check services
kubectl get services

# Check ingress
kubectl get ingress

# Get Minikube IP
minikube ip

# Add to /etc/hosts (Linux/Mac) or C:\Windows\System32\drivers\etc\hosts (Windows)
echo "$(minikube ip) auth-sys.local" >> /etc/hosts
```

### 5. Access Application

```bash
# Get service URLs
minikube service frontend-service --url
minikube service backend-service --url

# Or access via ingress
# http://auth-sys.local (add to hosts file)
```

### 6. Useful Kubernetes Commands

```bash
# View pod logs
kubectl logs -f deployment/backend-deployment
kubectl logs -f deployment/frontend-deployment
kubectl logs -f deployment/mysql-deployment

# Scale deployments
kubectl scale deployment backend-deployment --replicas=3
kubectl scale deployment frontend-deployment --replicas=2

# Port forwarding for debugging
kubectl port-forward service/backend-service 3000:3000
kubectl port-forward service/frontend-service 8080:80
kubectl port-forward service/mysql-service 3306:3306

# Execute commands in pods
kubectl exec -it deployment/backend-deployment -- npm run test
kubectl exec -it deployment/mysql-deployment -- mysql -u root -p

# Monitor resources
kubectl top pods
kubectl top nodes

# View events
kubectl get events --sort-by=.metadata.creationTimestamp

# Delete all resources
kubectl delete -f .

# Or use the cleanup script
chmod +x cleanup.sh
./cleanup.sh
```

### 7. Monitoring & Debugging

```bash
# Use the monitoring script
chmod +x monitor.sh
./monitor.sh

# Check pod status and restart if needed
kubectl get pods -w

# View detailed pod information
kubectl describe pod <pod-name>

# Check service endpoints
kubectl get endpoints
```

### 8. Production Deployment

For production deployment on cloud providers (AWS EKS, Google GKE, Azure AKS):

1. **Push images to container registry**:
```bash
# Build and tag for registry
docker build -t your-registry/auth-sys-backend:v1.0.0 ./backend
docker build -t your-registry/auth-sys-frontend:v1.0.0 ./frontend

# Push to registry
docker push your-registry/auth-sys-backend:v1.0.0
docker push your-registry/auth-sys-frontend:v1.0.0
```

2. **Update deployment images**:
```yaml
# In backend-deployment.yaml and frontend-deployment.yaml
spec:
  containers:
  - name: backend
    image: your-registry/auth-sys-backend:v1.0.0
```

3. **Configure persistent storage**:
```yaml
# Use cloud provider storage classes
storageClassName: gp2  # AWS
storageClassName: standard-rwo  # GKE
```

## 📡 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/register` | Register new user | ❌ |
| POST | `/api/v1/auth/login` | User login | ❌ |
| POST | `/api/v1/auth/logout` | User logout | ✅ |
| POST | `/api/v1/auth/refresh-token` | Refresh access token | ❌ |
| GET | `/api/v1/auth/current-user` | Get current user | ✅ |
| POST | `/api/v1/auth/change-password` | Change password | ✅ |
| PATCH | `/api/v1/auth/update-profile` | Update user profile | ✅ |
| PATCH | `/api/v1/auth/update-avatar` | Update user avatar | ✅ |

### Request/Response Examples

**Register User**
```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "name": "John Doe",
    "email": "john@example.com",
    "password": "securepassword"
  }'
```

**Login User**
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "securepassword"
  }'
```

**Change Password**
```bash
curl -X POST http://localhost:3000/api/v1/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "oldPassword": "currentpassword",
    "newPassword": "newsecurepassword"
  }'
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `NODE_ENV` | Environment mode | `development` | ❌ |
| `PORT` | Backend server port | `3000` | ❌ |
| `CORS_ORIGIN` | Frontend URL for CORS | `http://localhost:5173` | ❌ |
| `DB_HOST` | Database host | `localhost` | ✅ |
| `DB_USER` | Database username | `root` | ✅ |
| `DB_PASSWORD` | Database password | - | ✅ |
| `DB_NAME` | Database name | `auth_sys` | ✅ |
| `JWT_SECRET` | JWT signing secret | - | ✅ |
| `JWT_EXPIRES_IN` | JWT expiration time | `1d` | ❌ |
| `CLOUDINARY_CLOUD_NAME` | Cloudinary cloud name | - | ❌ |
| `CLOUDINARY_API_KEY` | Cloudinary API key | - | ❌ |
| `CLOUDINARY_API_SECRET` | Cloudinary API secret | - | ❌ |

### Database Schema

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    avatar_url TEXT DEFAULT NULL,
    refresh_token TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

## 🧪 Testing

### Running Tests

```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd frontend
npm test

# E2E tests
npm run test:e2e
```

### Manual Testing

```bash
# Health check
curl http://localhost:3000/health

# API status
curl http://localhost:3000/api/v1
```

## 🚀 Deployment

### Production Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Configure secure JWT secrets
- [ ] Set up SSL certificates
- [ ] Configure production database
- [ ] Set up monitoring & logging
- [ ] Configure backup strategies
- [ ] Review security headers
- [ ] Set up CI/CD pipeline

### Cloud Deployment Options

1. **AWS**: EKS + RDS + CloudFront
2. **Google Cloud**: GKE + Cloud SQL + Cloud CDN
3. **Azure**: AKS + Azure Database + Azure CDN
4. **Digital Ocean**: Kubernetes + Managed Database

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Guidelines

- Follow ESLint configuration
- Write meaningful commit messages
- Add tests for new features
- Update documentation
- Follow security best practices

## 📝 License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with ❤️ by [RushikeshGhodke](https://github.com/RushikeshGhodke)
- Powered by React, Node.js, and MySQL
- Icons by [Lucide](https://lucide.dev/)

---

### 📞 Support

If you have any questions or need help with setup, please:

1. Check the [Issues](https://github.com/RushikeshGhodke/authsys/issues) page
2. Create a new issue with detailed information
3. Contact: [linkedin.com/in/realrushikeshghodke]

**Happy Coding! 🚀**
