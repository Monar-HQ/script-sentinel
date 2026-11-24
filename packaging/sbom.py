"""Create a CycloneDX inventory from the active clean installation."""
import importlib.metadata
import json
import sys
from pathlib import Path

components = []
for distribution in importlib.metadata.distributions():
    name = distribution.metadata.get("Name", "unknown")
    components.append({"type":"library", "name":name, "version":distribution.version,
                       "purl":f"pkg:pypi/{name.lower().replace('_','-')}@{distribution.version}"})
result = {"bomFormat":"CycloneDX", "specVersion":"1.5", "version":1,
          "components":sorted(components,key=lambda component:component["name"].lower())}
with Path(sys.argv[1]).open("w",encoding="utf-8") as stream:
    json.dump(result,stream,indent=2)
