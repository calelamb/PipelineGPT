import json
import logging
import os
from typing import Any, Dict

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

logger = logging.getLogger(__name__)

OVERVIEW_SYSTEM_PROMPT = """You are a data analyst writing a concise narrative for a business user.

You will be given:
1. The original question/request the user asked
2. The dashboard that was built in response — its components, the SQL used, and a sample of the actual data returned

Your job is to write a short, plain-English narration that explains:
- What the dashboard as a whole reveals about the user's question
- For each individual component (chart, KPI, table): what it specifically shows and how it directly answers or supports the user's request

Rules:
- Be specific — reference actual numbers, trends, or patterns visible in the sample data where possible
- Keep each component explanation to 1-3 sentences
- Do not repeat the component title verbatim as the entire explanation
- Do not mention SQL or technical internals
- If a component errored and has no data, note it briefly and move on
- Write in second person ("This chart shows you...", "You can see here...")
- Return valid JSON only — no markdown fences, no extra text

Return this exact JSON shape:
{
  "summary": "<2-4 sentence overall narrative of how the dashboard answers the user's request>",
  "components": [
    {
      "id": "<component id>",
      "title": "<component title>",
      "narration": "<1-3 sentence explanation of what this specific component shows and how it answers the request>"
    }
  ]
}
"""


def _build_context(user_message: str, pipeline_result: Dict[str, Any]) -> str:
    """Build a compact JSON context for the LLM — avoids dumping thousands of data rows."""
    app_def = pipeline_result.get("app_definition", {})
    exec_results = pipeline_result.get("execution_results", {})

    components_context = []
    for comp in app_def.get("components", []):
        cid = comp.get("id", "")
        comp_result = exec_results.get(cid, {})
        status = comp_result.get("status", "unknown")
        row_count = comp_result.get("row_count", 0)
        error = comp_result.get("error", None)

        # Include up to 5 rows of sample data so the LLM can reference real numbers
        data = comp_result.get("data", [])
        sample = data[:5] if isinstance(data, list) else []

        components_context.append({
            "id": cid,
            "type": comp.get("type"),
            "title": comp.get("title"),
            "status": status,
            "row_count": row_count,
            "sample_data": sample,
            **({"error": error} if error else {}),
        })

    context = {
        "user_request": user_message,
        "app_title": app_def.get("app_title", ""),
        "app_description": app_def.get("app_description", ""),
        "components": components_context,
    }
    return json.dumps(context, default=str, indent=2)


def generate_overview(user_message: str, pipeline_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Call the LLM to produce a plain-English narration of how the dashboard
    answers the user's original request.

    Returns a dict with keys:
        summary    - overall narrative string
        components - list of {id, title, narration} dicts

    On any failure, returns a minimal fallback so the pipeline never breaks.
    """
    try:
        # Reuse the same client setup as intent_parser
        openrouter_key = os.getenv("OPENROUTER_API_KEY")
        if openrouter_key:
            api_key = openrouter_key
            base_url = os.getenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
        else:
            api_key = os.getenv("OPENAI_API_KEY")
            base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

        client = OpenAI(api_key=api_key, base_url=base_url)
        default_model = "openai/gpt-4o-mini" if openrouter_key else "gpt-4o-mini"
        model = os.getenv("OPENAI_MODEL", default_model)

        context_json = _build_context(user_message, pipeline_result)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": OVERVIEW_SYSTEM_PROMPT},
                {"role": "user", "content": context_json},
            ],
            temperature=0.4,
            max_completion_tokens=1024,
            timeout=30,
        )

        raw = response.choices[0].message.content or ""
        overview = json.loads(raw)
        logger.info("✓ Generated dashboard overview narration")
        return overview

    except json.JSONDecodeError as e:
        logger.warning(f"Overview JSON parse failed: {e}")
    except Exception as e:
        logger.warning(f"Overview generation failed: {e}")

    # Fallback — never crash the pipeline
    app_def = pipeline_result.get("app_definition", {})
    return {
        "summary": app_def.get("app_description", ""),
        "components": [
            {"id": c.get("id", ""), "title": c.get("title", ""), "narration": ""}
            for c in app_def.get("components", [])
        ],
    }
