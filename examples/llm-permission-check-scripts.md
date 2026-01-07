# LLM Permission Check: Script and Tool Execution

This document explains how the LLM-based permission checking system handles script and tool execution.

## Overview

When LLM permission checking is enabled, the system provides deep analysis of scripts and conservative handling of tool/binary execution to ensure security.

## Script Execution Detection

The system automatically detects when commands are executing scripts and analyzes the script content.

### Supported Script Types

The following script execution patterns are detected:

- **Bash/Shell**: `bash script.sh`, `sh script.sh`, `./script.sh`
- **Python**: `python script.py`, `python3 script.py`, `./script.py`
- **Node.js**: `node script.js`, `nodejs script.js`, `./script.js`
- **Ruby**: `ruby script.rb`, `./script.rb`
- **Perl**: `perl script.pl`, `./script.pl`

### Script Analysis Process

1. **Detection**: System detects script execution from the bash command
2. **Reading**: Attempts to read the script file content
3. **Analysis**: LLM analyzes ALL commands in the script
4. **Decision**:
   - If script is safe → `allow`
   - If script has unsafe commands → `deny`
   - If script cannot be read → `ask`

## Examples

### Example 1: Safe Script

**Script**: `deploy_local.sh`
```bash
#!/bin/bash
# Safe script - only modifies current directory
mkdir -p ./build
cp src/*.js ./build/
echo "Build complete"
```

**Command**: `bash deploy_local.sh`

**LLM Decision**: `allow`

**Reason**: Script only modifies files inside the current directory

---

### Example 2: Unsafe Script

**Script**: `deploy_prod.sh`
```bash
#!/bin/bash
# Unsafe script - modifies files outside current directory
rm -rf /var/www/old
cp -r ./build/* /var/www/
systemctl restart nginx
```

**Command**: `bash deploy_prod.sh`

**LLM Decision**: `deny`

**Reason**: Script modifies files outside current directory (`/var/www/`) and executes system commands

---

### Example 3: Unreadable Script

**Script**: `mystery.sh` (file doesn't exist or no read permission)

**Command**: `bash mystery.sh`

**LLM Decision**: `ask`

**Reason**: Cannot read script content, cannot verify safety - user should confirm

---

### Example 4: Python Data Processing

**Script**: `process_data.py`
```python
#!/usr/bin/env python3
# Safe Python script - only reads and processes data
import json

with open('./data.json', 'r') as f:
    data = json.load(f)

# Process data
result = [item for item in data if item['active']]

with open('./output.json', 'w') as f:
    json.dump(result, f)

print("Processing complete")
```

**Command**: `python3 process_data.py`

**LLM Decision**: `allow`

**Reason**: Script only reads/writes files in current directory

---

### Example 5: Python with System Commands

**Script**: `backup.py`
```python
#!/usr/bin/env python3
import os
import subprocess

# Unsafe - modifies system directories
subprocess.run(['mkdir', '-p', '/backup'])
subprocess.run(['cp', '-r', './data', '/backup/'])
```

**Command**: `python backup.py`

**LLM Decision**: `deny`

**Reason**: Script creates directories and copies files outside current directory

---

## Tool and Binary Execution

For compiled binaries or unknown tools, the LLM cannot inspect internal behavior and adopts a conservative approach.

### Known Safe Tools

Common read-only utilities are generally allowed:
- `ls`, `cat`, `grep`, `find`, `head`, `tail`
- `git status`, `git log`, `git diff`
- `pwd`, `whoami`, `date`

### Unknown Tools

For unknown binaries or tools, the system defaults to asking the user:

**Example**: `./custom-build-tool`

**LLM Decision**: `ask`

**Reason**: Cannot verify what the binary will do internally

### Package Managers

Package managers might download and execute code, so they require user confirmation:

**Examples**:
- `npm install` → `ask`
- `pip install package` → `ask`
- `cargo build` → `ask`

**Reason**: These tools might download and execute unknown code

---

## Configuration

Enable LLM permission checking in your `opencode.json`:

```json
{
  "llmPermissionCheck": {
    "enabled": true,
    "model": "anthropic/claude-sonnet-4"
  }
}
```

## Security Principles

When analyzing scripts and tools, the LLM follows these principles:

1. **Read Operations**: Always allowed
2. **Modifications Inside Current Directory**: Allowed
3. **Modifications Outside Current Directory**: Denied
4. **Script Analysis**: ALL commands in the script must follow the above rules
5. **Unknown Tools**: Conservative approach - ask user for confirmation

## Logging

When script execution is detected, the system logs:
- Script path
- Whether content was successfully read
- LLM's decision and reasoning

Check logs for debugging:
```bash
# View LLM permission check logs
opencode logs | grep "LLM permission check"
```

## Best Practices

### For Users

1. **Review script content** before running if LLM asks for confirmation
2. **Use relative paths** in scripts to stay within current directory
3. **Avoid system-wide modifications** in scripts when using LLM checks

### For Script Authors

1. **Keep scripts focused** on current project directory
2. **Document external dependencies** clearly
3. **Use explicit paths** rather than relative paths that might escape current directory
4. **Add comments** explaining what the script does

## Limitations

1. **Nested Script Calls**: If a script calls another script, only the first level is analyzed
2. **Dynamic Code**: Scripts that generate and execute code dynamically cannot be fully analyzed
3. **Obfuscated Scripts**: Heavily obfuscated code might be difficult for LLM to analyze accurately
4. **Binary Tools**: Internal behavior of compiled binaries cannot be inspected

## Troubleshooting

### LLM Denies Safe Script

If the LLM incorrectly denies a safe script:

1. Check if the script modifies files outside current directory
2. Verify all paths in the script are relative to current directory
3. Add the operation to manual permission rules if needed:
   ```json
   {
     "permission": {
       "bash": {
         "bash safe-script.sh": "allow"
       }
     }
   }
   ```

### LLM Cannot Read Script

If the script file cannot be read:

1. Check file exists at the specified path
2. Verify read permissions on the script file
3. Ensure the path is correct (relative or absolute)

---

## Summary

The LLM permission checking system provides enhanced security by:

✅ Automatically detecting script execution
✅ Reading and analyzing script content
✅ Checking ALL commands in scripts against security principles
✅ Adopting conservative approach for unknown tools
✅ Providing clear reasoning for decisions

This deep analysis helps prevent accidental or malicious modifications to files outside your project directory while still allowing legitimate development operations.
