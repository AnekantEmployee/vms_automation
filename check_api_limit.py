import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()


def test_gemini_keys():
    """Test all Gemini keys"""
    keys = [
        os.getenv("GOOGLE_API_KEY_1"),
        os.getenv("GOOGLE_API_KEY_2"),
        os.getenv("GOOGLE_API_KEY_3"),
        os.getenv("GOOGLE_API_KEY_4"),
        os.getenv("GOOGLE_API_KEY_5"),
        os.getenv("GOOGLE_API_KEY_6"),
        os.getenv("GOOGLE_API_KEY_7"),
        os.getenv("GOOGLE_API_KEY_8"),
        os.getenv("GOOGLE_API_KEY_9"),
        os.getenv("GOOGLE_API_KEY_10"),
    ]

    working_keys = []
    model_name = os.getenv("MODEL_NAME", "gemini-2.5-flash")
    print("Testing Model:", model_name)
    for i, key in enumerate(keys, 1):
        if not key:
            continue

        try:
            genai.configure(api_key=key)
            model = genai.GenerativeModel(model_name)
            response = model.generate_content("Hello")
            print(f"Key {i}: Working")
            working_keys.append(i)
        except Exception as e:
            if "429" in str(e):
                print(f"Key {i}: Rate limited")
            else:
                print(f"Key {i}: {str(e)[:50]}")

    return working_keys


if __name__ == "__main__":
    print("Testing API availability...")

    working_gemini = test_gemini_keys()

    print(f"\nSummary:")
    print(f"Working Gemini keys: {len(working_gemini)}/9")

    if len(working_gemini) > 0:
        print(f"\nUse Gemini keys: {working_gemini}")
