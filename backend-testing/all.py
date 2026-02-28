import json
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine.pipeline import run_pipeline

# Create outputs folder if it doesn't exist
Path("outputs").mkdir(exist_ok=True)

# Run pipeline
result = run_pipeline(
    user_message="What is the sales trend?",
    existing_app=None,
    filters={},
    role="analyst",
)

# Save to file with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = Path("outputs") / f"output_{timestamp}.json"

with open(output_file, "w") as f:
    json.dump(result, f, indent=2)

print(f"Output saved to {output_file}")