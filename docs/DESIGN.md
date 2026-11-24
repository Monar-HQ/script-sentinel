# ScriptSentinel product design

## Intent

A security engineer reviewing a checkout on a desk monitor, often beside a code
editor, needs a low-glare evidence workspace; a store owner needs the next step
to be understandable. The product uses the master plan's graphite and signal
yellow identity, restricted to controls and small workflow identifiers.
Headings name the task directly. Avoid paired slogans, promotional claims and
large decorative accent panels in the working console.

## Tokens

Background #101110; rail #141614; raised surface #171917; line #343a33;
primary text #f1f3e9; secondary text #b0b6a9; action yellow #dffc70;
risk text #ff9990. The neutral palette is intentionally dark; severity also
appears as words. Controls use a 6px radius and visible 2px keyboard focus.

System sans typography carries the product; monospace is limited to evidence,
code and compact metadata. No remote font, analytics or asset requests are needed.
Fixed product type scales replace responsive display theatrics.

## Layout and behavior

A persistent navigation rail becomes a horizontal scrollable navigation on mobile.
The overview introduces a real workflow and offers a synthetic demo before setup.
Inventory is a filterable table. Baseline decisions, monitoring, patch review,
research and the local ledger have separate task views. Evidence details are
progressively disclosed; raw JSON is available for experts.

State transitions are short. Reduced motion disables animation and transitions.
All dynamic evidence uses textContent and DOM construction, not HTML injection.
Loading, empty, error, unavailable and successful states are explicit. Controls
disable while an operation is in progress. The UI never silently applies a fix.

The GitHub hero is a separate static brand composition. Screenshots are generated
from the actual running console using packaging/preview_console.py, not invented
dashboard figures. Historical red assets remain in the repository as earlier
design work; the v1 README references the new assets.
