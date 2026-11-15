# Case NNN: <short title>

| Field | Value |
|---|---|
| Date and time (UTC) | |
| Host / user | |
| Alert / rule ID and level | |
| Data source | Windows Security Event 4688 via Wazuh |
| ATT&CK technique | |
| Verdict | True positive / False positive / Benign true positive |
| Severity | Low / Medium / High |

## 1. What fired
One or two sentences: which rule, on which event.

## 2. Evidence
The key fields (user, process, parent process, command line) and a screenshot or log line.

## 3. Investigation
Questions answered in order: Who ran it? What is it? Where did it start from (parent)? Is the path normal? Does it match a known tool or admin task? What happened before and after?

## 4. Verdict and reasoning
Why this verdict, in 3 to 5 lines. Name the one or two facts that decided it.

## 5. Action
What a Tier 1 analyst does next (close, escalate to Tier 2, contain, ask the user).

## 6. Detection improvement
How to cut noise or catch more (exclusions, extra fields, a new rule).
