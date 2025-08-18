import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def search_vuldb_by_keyword(api_key, keyword):
    """
    Search VulDB by keyword when direct CVE lookup fails
    """
    url = "https://vuldb.com/?api"

    post_fields = {
        "apikey": api_key,
        "search": keyword,
        "details": 1,
    }

    try:
        request = Request(
            url,
            urlencode(post_fields).encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Python VulDB Client",
            },
        )

        with urlopen(request) as response:
            response_data = response.read().decode("utf-8")

        parsed_json = json.loads(response_data)
        print(f"\n🔍 Search results for '{keyword}':")
        print(json.dumps(parsed_json["result"], indent=2))

        return parsed_json["result"]

    except Exception as e:
        print(f"Search error: {e}")
        return None


if __name__ == "__main__":
    # Replace with your actual API key
    API_KEY = "13a4fe0bc34d213a5d211f25f04373ff"
    CVE_ID = "CVE-2024-4282"

    # Try searching by year and number
    search_term = CVE_ID.split("CVE")[-1][1:]
    print(search_term)
    print(f"Searching for: {search_term}")
    search_result = search_vuldb_by_keyword(API_KEY, search_term)
