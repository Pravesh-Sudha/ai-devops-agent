import json
import urllib.request
import urllib.error
import boto3

# ---------------- CONFIG ---------------- #
GEMINI_MODEL = "gemini-2.5-flash"
SECRET_NAME = "gemini-api-key"
REGION_NAME = "us-east-1"  # change if needed

GEMINI_API_KEY = None


# --------- FETCH SECRET (CACHED) -------- #
def get_gemini_api_key():
    global GEMINI_API_KEY

    if GEMINI_API_KEY:
        return GEMINI_API_KEY

    client = boto3.client("secretsmanager", region_name=REGION_NAME)
    response = client.get_secret_value(SecretId=SECRET_NAME)
    secret = json.loads(response["SecretString"])

    GEMINI_API_KEY = secret["GEMINI_API_KEY"]
    return GEMINI_API_KEY


# ------------ DATA EXTRACTORS ----------- #
def extract_relevant_findings(terrascan_results: dict) -> dict:
    violations = terrascan_results.get("violations", [])
    summary = terrascan_results.get("scan_summary", {})

    structured = {
        "summary": {
            "total_violations": summary.get("violated_policies", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0)
        },
        "violations": []
    }

    for v in violations:
        structured["violations"].append({
            "rule_id": v.get("rule_id"),
            "rule_name": v.get("rule_name"),
            "severity": v.get("severity"),
            "description": v.get("description"),
            "resource_type": v.get("resource_type"),
            "resource_name": v.get("resource_name"),
            "file": v.get("file"),
            "line": v.get("line")
        })

    return structured


# ------------- PROMPT BUILDER ------------ #
def build_prompt(findings: dict) -> str:
    return f"""
You are a senior DevOps and Terraform security reviewer.

Analyze the Terrascan findings below and provide:

1. 🚨 Security issues ordered by severity
2. 🛠 Terraform remediation suggestions
3. ⚖️ Production risk explanation
4. 📌 Final verdict:
   - APPROVE
   - APPROVE_WITH_CHANGES
   - REJECT

Rules:
- Be concise
- Use bullet points
- Focus on AWS (ALB, ECS, VPC, IAM)
- Ignore Terrascan scan_errors
- Do NOT repeat raw JSON

Findings:
{json.dumps(findings, indent=2)}
"""


# ------------- GEMINI CALL --------------- #
def call_gemini(prompt: str) -> str:
    api_key = get_gemini_api_key()

    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={api_key}"
    )

    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ]
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read())
            return result["candidates"][0]["content"]["parts"][0]["text"]

    except urllib.error.HTTPError as e:
        return f"Gemini API HTTP error: {e.read().decode()}"

    except Exception as e:
        return f"Unexpected error calling Gemini: {str(e)}"


# ------------- LAMBDA HANDLER ------------ #
def lambda_handler(event, context):
    """
    Expected payload:
    {
      "results": {
        "violations": [...],
        "scan_summary": {...}
      }
    }
    """

    try:
        results = event.get("results")
        if not results:
            return {
                "statusCode": 400,
                "error": "Missing Terrascan results in payload"
            }

        findings = extract_relevant_findings(results)
        prompt = build_prompt(findings)
        review = call_gemini(prompt)

        return {
            "statusCode": 200,
            "verdict_summary": findings["summary"],
            "ai_review": review
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "error": str(e)
        }
