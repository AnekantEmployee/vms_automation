import sys
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent))

from backend.services.asset_service import run_asset_agent


if __name__ == "__main__":
    print("\n=== Asset Criticality & Risk Agent ===")

    ip                  = input("Target IP address                                            : ").strip()
    declared_role       = input("Asset role          [Enter to let AI infer]                  : ").strip() or "Unknown / Let AI infer"
    data_classification = input("Data classification [public/internal/confidential/restricted] : ").strip() or "internal"
    environment         = input("Environment         [production/staging/development/dr]       : ").strip() or "production"
    owner               = input("Owner email / team                                            : ").strip() or "unknown"

    result = run_asset_agent(
        ip=ip,
        declared_role=declared_role,
        data_classification=data_classification,
        environment=environment,
        owner=owner,
    )

    print(json.dumps(result, indent=2, default=str))

    out = Path("results") / f"{ip.replace('.', '_')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"\nResult saved to: {out}")
