import json
import urllib.request
import urllib.error
import boto3

GEMINI_MODEL = "gemini-2.5-flash"
SECRET_NAME = "gemini-api-key-2"
REGION_NAME = "us-east-1"

GEMINI_API_KEY = None


def get_gemini_api_key():
    global GEMINI_API_KEY

    if GEMINI_API_KEY:
        return GEMINI_API_KEY

    client = boto3.client("secretsmanager", region_name=REGION_NAME)
    response = client.get_secret_value(SecretId=SECRET_NAME)
    secret = json.loads(response["SecretString"])

    GEMINI_API_KEY = secret["GEMINI_API_KEY"]
    return GEMINI_API_KEY


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

def build_prompt(findings: dict) -> str:
    return f"""
You are a senior DevOps and Terraform security reviewer with strong AWS architecture experience.

Analyze the Terrascan findings below and provide:

1. 🚨 Security issues ordered by severity
2. 🛠 Terraform remediation suggestions
3. ⚖️ Production risk explanation
4. 📌 Final verdict:
   - APPROVE
   - APPROVE_WITH_CHANGES
   - REJECT

Evaluation rules (IMPORTANT):
- If the application is exposed ONLY over HTTP (no HTTPS listener, no TLS), the verdict MUST be **REJECT**
- If HTTPS is configured at an AWS Application Load Balancer using ACM (TLS termination at ALB), this is a **valid and common AWS architecture**
- Do NOT reject solely because traffic between ALB and targets uses HTTP
- In such cases, prefer **APPROVE_WITH_CHANGES** with a clear security justification
- End-to-end encryption (ALB → target HTTPS) is a best practice but NOT mandatory unless explicitly required
- VPC Flow Logs, X-Ray, and similar observability issues should NOT cause rejection alone
- Ignore Terrascan scan_errors
- Do NOT repeat raw JSON

Output guidelines:
- Be concise
- Use bullet points
- Focus on AWS services (ALB, VPC, IAM, Lambda, ECS)
- Use real-world production reasoning, not scanner-only logic

Findings:
{json.dumps(findings, indent=2)}
"""


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


def lambda_handler(event, context):

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
