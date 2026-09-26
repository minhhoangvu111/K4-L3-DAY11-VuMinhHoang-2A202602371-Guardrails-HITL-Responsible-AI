import asyncio
import sys
from pathlib import Path

# Add src to sys.path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from assignment.pipeline import run_assignment_suite

async def main():
    print("Generating outputs/results.json...")
    res = await run_assignment_suite()
    print("Done! Results generated successfully.")
    print("Safe queries blocked:", sum(1 for q in res["safe_queries"] if q.get("blocked")))
    print("Attack queries blocked:", sum(1 for q in res["attack_queries"] if q.get("blocked")))
    print("Rate limit data:", res["rate_limit"])

if __name__ == "__main__":
    asyncio.run(main())
