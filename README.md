# AgriYogi - Farm Blockchain Platform

This folder contains a self-contained Flask site for viewing and appending to the agricultural blockchain.

The site persists a simple ledger in a local SQLite database file `ledger.db` (saved next to this module). That makes the chain survive server restarts.

Run locally:

```powershell
cd "C:\Users\smand\Desktop\blockchain_site"
python -m pip install -r requirements.txt
python web_app.py
```

Open http://127.0.0.1:5000 in your browser.

Reset the ledger by stopping the server and deleting `ledger.db`.
