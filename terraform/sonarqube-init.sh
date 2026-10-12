#!/bin/bash
set -e

# System update
dnf update -y
dnf install -y docker git

# Start Docker
systemctl enable docker
systemctl start docker
usermod -aG docker ec2-user

# Required by SonarQube/Elasticsearch
echo "vm.max_map_count=524288" >> /etc/sysctl.conf
echo "fs.file-max=131072"      >> /etc/sysctl.conf
sysctl -p

# Create data directories
mkdir -p /opt/sonarqube/{data,logs,extensions}
chown -R 1000:1000 /opt/sonarqube

# Run SonarQube Community Edition
docker run -d \
  --name sonarqube \
  --restart unless-stopped \
  -p 9000:9000 \
  -v /opt/sonarqube/data:/opt/sonarqube/data \
  -v /opt/sonarqube/logs:/opt/sonarqube/logs \
  -v /opt/sonarqube/extensions:/opt/sonarqube/extensions \
  sonarqube:community

# Wait for SonarQube to be ready
echo "Waiting for SonarQube to start..."
for i in $(seq 1 60); do
  if curl -sf http://localhost:9000/api/system/status | grep -q '"status":"UP"'; then
    echo "SonarQube is UP after $((i*5))s"
    break
  fi
  sleep 5
done

# Change default admin password using the injected value
SONAR_PASS="${sonar_password}"

curl -sf -u admin:admin -X POST \
  "http://localhost:9000/api/users/change_password" \
  -d "login=admin&password=$SONAR_PASS&previousPassword=admin" || true

# Create CI/CD token
TOKEN=$(curl -sf -u "admin:$SONAR_PASS" -X POST \
  "http://localhost:9000/api/user_tokens/generate" \
  -d "name=gitlab-ci-token" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','FAILED'))" \
  || echo "FAILED")

echo "SONAR_TOKEN=$TOKEN" > /opt/sonarqube/ci-token.env
echo "SonarQube ready. Token saved to /opt/sonarqube/ci-token.env"
