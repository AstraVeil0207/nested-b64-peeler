# nested-b64-peeler
> Safe recursive nested Base64 payload peeler. **Never executes any decoded content.**

A static analysis tool for peeling multi-layer Base64 obfuscated shell one-liners.
It only decodes and records each layer, no `eval`, no subprocess, no shell execution.

## What it does
Attackers often hide shell code like this:
```bash
echo "BASE64_PAYLOAD" | base64 -d | bash
printf %s "BASE64_PAYLOAD" | base64 --decode | sh

```
# Basic usage
python3 decode_nested_b64.py payload.txt

# Custom output file, preview first 20 lines
python3 decode_nested_b64.py payload.txt -o result.txt --show 20
