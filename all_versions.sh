#!/bin/bash

echo "========== SISTEMA ==========" && \
lsb_release -d && uname -r && \
echo && \
echo "========== GLOBAL ==========" && \
python3 --version && \
java -version 2>&1 | head -n 1 && \
echo "node $(node --version)" && \
echo "npm $(npm --version)" && \
echo "yarn $(yarn --version)" && \
docker --version && docker compose version && \
git --version && \
rustc --version && cargo --version && \
solana --version && anchor --version && \
psql --version && \
nginx -v 2>&1 && \
echo "mn $(mn --version 2>&1 | head -n 1)" && \
ovs-vsctl --version | head -n 1 && \
tshark -v | head -n 1 && \
echo && \
echo "========== RYU ==========" && \
cd ~/cyberdefense/controller && \
pyenv local 3.10.14 && \
source venv/bin/activate && \
python --version && \
ryu-manager --version && \
deactivate && \
echo && \
echo "========== BACKEND ==========" && \
cd ~/cyberdefense/backend && \
source venv/bin/activate && \
python3 --version && \
echo "FastAPI $(pip show fastapi | grep Version)" && \
echo "Uvicorn $(pip show uvicorn | grep Version)" && \
deactivate && \
echo && \
echo "========== IA ==========" && \
cd ~/cyberdefense/ai && \
source iaenv/bin/activate && \
python3 --version && \
echo "Pandas $(pip show pandas | grep Version)" && \
echo "Scikit-learn $(pip show scikit-learn | grep Version)" && \
deactivate && \
echo && \
echo "========== FRONTEND REACT ==========" && \
cd ~/cyberdefense/frontend && \
npm list react --depth=0 && \
npm list react-dom --depth=0
