"""
Lab 11 — Configuration & API Key Setup
"""
import os

from google import genai
from google.genai import types


def setup_api_key():
    """Load ShopAIKey credentials and configure SDK environments."""
    if "SHOPAIKEY_API_KEY" not in os.environ:
        os.environ["SHOPAIKEY_API_KEY"] = input("Enter ShopAIKey API Key: ")

    shopaikey_key = os.environ["SHOPAIKEY_API_KEY"]

    # ADK via LiteLLM reads OpenAI-style env vars.
    os.environ.setdefault("OPENAI_API_KEY", shopaikey_key)
    os.environ.setdefault("OPENAI_API_BASE", "https://api.shopaikey.com/v1")

    # google-genai direct client uses explicit http_options in create_genai_client().
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "1"
    print("ShopAIKey provider configured.")


def create_genai_client() -> genai.Client:
    """Create a google-genai client routed through ShopAIKey Gemini proxy."""
    api_key = os.environ.get("SHOPAIKEY_API_KEY", "")
    user_agent = os.environ.get(
        "SHOPAIKEY_USER_AGENT",
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
    )

    return genai.Client(
        vertexai=True,
        http_options=types.HttpOptions(
            base_url=os.environ.get("SHOPAIKEY_GENAI_BASE_URL", "https://api.shopaikey.com"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": user_agent,
            },
        ),
    )


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
