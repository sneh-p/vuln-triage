import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agents._lib.parsers import cavelo

with open('cavelo_test.csv', 'r') as f:
    results = list(cavelo.parse(f))
    print("Parsed count:", len(results))
    for r in results:
        print(r)
