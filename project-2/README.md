# Project 1 - Building and Testing a Prompt Injection Defence Layer

### 1. Overview

This project implements a basic security defence layer for an LLM-powered employee assistant.

The application uses a locally hosted Llama 3.2:1B model through Ollama and a Python Flask backend.

The objective is to identify and mitigate prompt injection attacks and sensitive-information disclosure.

### 2. Technology Stack

- Python
- Flask
- Ollama
- Llama 3.2:1B
- Regular Expressions
- Burp Suite Community Edition

### 3. Security Features

- Input validation.
- Maximum input length of 500 characters.
- Regex-based prompt injection detection.
- Base64-encoded payload inspection.
- Sensitive-information detection.
- Output redaction.
- Secret isolation from the LLM system prompt.

### 4. Project Structure

```text
AI-Security-Capstone/
├── app.py
├── validate.py
├── output_scanner.py
├── requirements.txt
├── test_legitimate.py
├── test_output_scanner.py
├── test_validate.py
└── README.md
```

### 5. Prerequisites

- Python 3.10 or later (use a version compatible with the installed dependencies).
- Ollama installed and running.
- Llama 3.2:1B model downloaded.
- Required Python packages.
- Burp Suite Community Edition (for security testing).

### 6. Installation

Clone the repository:

```bash
git clone https://github.com/sudipto-acc/ai-application-security-capstone.git
cd project-2
```

Create a virtual environment:

```bash
python -m venv ai-lab
```

Activate it on Linux:

```bash
source ai-lab/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Download the model:

```bash
ollama pull llama3.2:1b
```

Start Ollama if it is not already running:

```bash
ollama serve
```

### 7. Running the Application

Start the Flask application:

```bash
python app.py
```

The application runs locally at:

`http://127.0.0.1:5000`

### 8. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Application interface |
| GET | `/health` | Application health check |
| POST | `/ask` | Baseline endpoint |
| POST | `/ask-secure` | Protected endpoint |

Example protected request:

```bash
curl -X POST http://127.0.0.1:5000/ask-secure \
-H "Content-Type: application/json" \
-d '{"message":"How can I reset my employee portal password?"}'
```

### 9. Testing

The project includes:
- Input validation tests.
- Output scanner tests.
- Legitimate-query tests.
- Prompt injection attack tests.
- HTTP-level security testing using Burp Suite Repeater.


### 10. Assessment Results

| Assessment | Result |
|---|---|
| Input validation | 8/8 tests passed |
| Output scanner | 9/9 tests passed |
| Legitimate queries | 10/10 accepted |
| Baseline attack tests | 3/5 triggered |
| Protected attack tests | 5/5 rejected |
| Secret isolation | Successful retest |

