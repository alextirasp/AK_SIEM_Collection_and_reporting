# Terminal 1 — start the proxy
pip3 install flask flask-cors requests
python3 akamai_siem_proxy.py --edgerc ~/.edgerc.txt  --port 8000

# Terminal 2 — serve the HTML (optional, only needed if you want a proper URL)
python3 -m http.server 3000
# then open http://localhost:3000