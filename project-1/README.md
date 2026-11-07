# Project 1 - Vulnerable-by-Design AI Chat Application

## Prerequisites
- Kali Linux
- Python 3.10+
- Ollama running locally
- Model `llama3` downloaded

## Setup
```bash
cd ~/ai-security-capstone/project-1
python3 -m venv ai-lab
source ai-lab/bin/activate
pip install -r requirements.txt
```

## Start Ollama
In a terminal:
```bash
ollama serve
```
If Ollama is already running as a system service, leave it running and do not
start a second server.

Check the model:
```bash
ollama list
ollama run llama3
```
Exit the model with `/bye`.

## Start Flask
In another terminal:
```bash
cd ~/ai-security-capstone/project-1
source ai-lab/bin/activate
python app.py
```

Open `http://127.0.0.1:5000` in Kali's browser.

## Verify
In another terminal:
```bash
curl -s http://127.0.0.1:5000/health
```
Expected: JSON with `"status": "ok"`, `"ollama": "reachable"` and
`"configured_model": "llama3"`.

Test the API:
```bash
curl -s -X POST http://127.0.0.1:5000/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Hello. What can you help me with?"}'
```

## Model configuration
The default model is `llama3`. To use another locally installed model:
```bash
OLLAMA_MODEL=llama3.2:1b python app.py
```

## Known intentional weaknesses for the assessment
- No user authentication or authorization on `/chat`.
- No prompt-injection mitigation; user text is passed directly to the model.
- Synthetic internal context is included in the system prompt for controlled
  prompt-leakage exercises.

The page uses `textContent` to display model output, so it does not intentionally
introduce browser-side HTML injection. Do not report an issue as confirmed
unless your test demonstrates it.

## Stop
Press `Ctrl+C` in the Flask terminal. Ollama can remain running for the next test.
