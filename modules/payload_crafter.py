"""
AI Payload Crafter — Uses Claude to generate practical, phase-specific payloads.
"""
import anthropic
import json
import os

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    return _client


PHASE_PROMPTS = {
    "web": {
        "sqli": """You are an expert penetration tester. Generate practical SQL injection payloads for testing the endpoint.
Target: {target}:{port} | URL/Param: {context}
Service info: {service_info}

Provide a JSON object with this exact structure:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": ["step1", "step2"],
  "tools": ["sqlmap command", "burp tip"],
  "risk": "HIGH/MEDIUM/LOW",
  "notes": "..."
}}

Include: error-based, union-based, boolean-blind, time-based blind SQLi. Make payloads realistic for the detected DB if known.""",

        "xss": """You are an expert penetration tester. Generate practical XSS payloads.
Target: {target}:{port} | Context: {context}
Service info: {service_info}

Provide JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "reflected/stored/dom", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": ["step1"],
  "tools": [".."],
  "risk": "HIGH/MEDIUM/LOW",
  "notes": "..."
}}

Include: reflected, stored, DOM-based, polyglot, filter bypass variants.""",

        "lfi_rfi": """Generate LFI/RFI payloads for penetration testing.
Target: {target}:{port} | Parameter: {context}
Service info: {service_info}

JSON format:
{{
  "payloads": [
    {{"payload": "...", "type": "LFI/RFI/path-traversal", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}""",

        "ssrf": """Generate SSRF payloads for penetration testing.
Target: {target}:{port} | Context: {context}
Service info: {service_info}

JSON format:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}

Include: internal service probing, AWS metadata, cloud IMDS, bypass techniques.""",

        "cmdi": """Generate OS command injection payloads.
Target: {target}:{port} | Parameter: {context}
Service info: {service_info}

JSON format:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}

Include: Linux and Windows variants, blind injection, out-of-band.""",

        "auth_bypass": """Generate authentication bypass payloads and techniques.
Target: {target}:{port} | Context: {context}
Service info: {service_info}

JSON format:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}

Include: SQL auth bypass, default credentials, JWT attacks, password spraying list.""",

        "xxe": """Generate XXE (XML External Entity) payloads.
Target: {target}:{port} | Endpoint: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}""",

        "idor": """Generate IDOR testing methodology and payloads.
Target: {target}:{port} | Endpoint: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}""",
    },

    "network": {
        "smb": """Generate SMB penetration testing commands and payloads.
Target: {target}:{port}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "enum/exploit/bruteforce", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["smbclient command", "crackmapexec command", "impacket command"],
  "risk": "...",
  "notes": "..."
}}

Include: null session, share enum, EternalBlue check, credential testing, pass-the-hash.""",

        "ssh": """Generate SSH penetration testing techniques.
Target: {target}:{port}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["hydra command", "medusa command", "ssh-audit command"],
  "risk": "...",
  "notes": "..."
}}""",

        "ftp": """Generate FTP penetration testing payloads.
Target: {target}:{port}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}

Include: anonymous login, bounce attack, brute force.""",

        "rdp": """Generate RDP penetration testing techniques.
Target: {target}:{port}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["ncrack command", "crowbar command", "BlueKeep check"],
  "risk": "...",
  "notes": "..."
}}""",

        "database": """Generate database penetration testing payloads.
Target: {target}:{port}
Service: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}

Cover: default creds, unauthenticated access, data exfiltration commands, privilege escalation.""",

        "generic": """Generate network penetration testing payloads for this service.
Target: {target}:{port}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}""",
    },

    "mobile": {
        "android": """Generate Android penetration testing methodology and payloads.
Target app/API: {target}:{port} | Context: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": ["adb command", "frida script hint", "apktool command"],
  "tools": ["MobSF", "Frida", "apktool", "jadx"],
  "risk": "...",
  "notes": "..."
}}

Cover: insecure data storage, exported activities, intent fuzzing, API endpoint testing, SSL pinning bypass, root detection bypass.""",

        "ios": """Generate iOS penetration testing methodology.
Target app/API: {target}:{port} | Context: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": ["objection command", "frida script hint"],
  "tools": ["Objection", "Frida", "iDB", "MobSF"],
  "risk": "...",
  "notes": "..."
}}

Cover: keychain dumping, SSL pinning bypass, Frida hooks, plist inspection, jailbreak detection bypass.""",

        "api": """Generate mobile API penetration testing payloads.
Target API: {target}:{port} | Endpoint: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["Burp Suite", "Postman", "jwt_tool"],
  "risk": "...",
  "notes": "..."
}}

Cover: JWT attacks, broken object-level auth, mass assignment, rate limit bypass, API key exposure.""",
    },

    "redteam": {
        "phishing": """Generate red team phishing methodology.
Target org/domain: {target} | Context: {context}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["GoPhish", "SET", "evilginx2"],
  "risk": "...",
  "notes": "..."
}}""",

        "privesc_linux": """Generate Linux privilege escalation techniques for post-exploitation.
Target: {target} | Context: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["linpeas command", "linux-exploit-suggester", "sudo -l"],
  "risk": "...",
  "notes": "..."
}}

Cover: SUID/SGID, cron jobs, writable /etc/passwd, sudo misconfig, kernel exploits.""",

        "privesc_windows": """Generate Windows privilege escalation techniques.
Target: {target} | Context: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["winPEAS command", "PowerUp.ps1", "SharpUp"],
  "risk": "...",
  "notes": "..."
}}

Cover: AlwaysInstallElevated, unquoted service paths, weak service perms, token impersonation.""",

        "lateral": """Generate lateral movement techniques for red teaming.
Target network: {target} | Context: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": ["impacket", "crackmapexec", "BloodHound"],
  "risk": "...",
  "notes": "..."
}}

Cover: pass-the-hash, pass-the-ticket, WMI exec, PSExec, DCOM.""",

        "persistence": """Generate persistence mechanisms for red team post-exploitation.
Target: {target} | Context: {context}
Service info: {service_info}

JSON:
{{
  "payloads": [
    {{"payload": "...", "type": "...", "description": "...", "expected_result": "..."}}
  ],
  "manual_steps": [".."],
  "tools": [".."],
  "risk": "...",
  "notes": "..."
}}

Cover: cron/scheduled tasks, startup items, web shells, registry run keys, service installation.""",
    },
}


def craft_payloads(
    target: str,
    port: int,
    category: str,      # "web", "network", "mobile", "redteam"
    attack_type: str,   # e.g. "sqli", "smb", "android"
    context: str = "",
    service_info: str = "",
) -> dict:
    """Ask Claude to craft practical payloads for the given target/attack type."""
    prompt_template = PHASE_PROMPTS.get(category, {}).get(attack_type)
    if not prompt_template:
        prompt_template = PHASE_PROMPTS["network"]["generic"]

    prompt = prompt_template.format(
        target=target,
        port=port,
        context=context or "N/A",
        service_info=service_info or "unknown service",
    )

    try:
        client = _get_client()
        msg = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text.strip()

        # Extract JSON block
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        parsed = json.loads(text)
        parsed["target"] = target
        parsed["port"] = port
        parsed["category"] = category
        parsed["attack_type"] = attack_type
        return parsed

    except json.JSONDecodeError:
        return {
            "target": target,
            "port": port,
            "category": category,
            "attack_type": attack_type,
            "payloads": [],
            "manual_steps": [],
            "tools": [],
            "risk": "UNKNOWN",
            "notes": text if "text" in dir() else "Failed to parse AI response",
            "raw_response": text if "text" in dir() else "",
        }
    except Exception as e:
        return {
            "error": str(e),
            "target": target,
            "port": port,
            "category": category,
            "attack_type": attack_type,
            "payloads": [],
        }


def get_attack_surface(open_ports: list[dict]) -> list[dict]:
    """
    Given open ports from recon, suggest which attacks to run.
    Returns a list of suggested attack modules with metadata.
    """
    suggestions = []
    port_map = {p["port"]: p for p in open_ports}

    # Web
    for p in [80, 443, 8080, 8443, 8888]:
        if p in port_map:
            for attack in ["sqli", "xss", "lfi_rfi", "ssrf", "cmdi", "auth_bypass", "xxe", "idor"]:
                suggestions.append({
                    "port": p,
                    "category": "web",
                    "attack_type": attack,
                    "service": port_map[p].get("service", "HTTP"),
                    "priority": "HIGH" if attack in ("sqli", "cmdi", "auth_bypass") else "MEDIUM",
                })

    # SMB
    for p in [445, 139]:
        if p in port_map:
            suggestions.append({"port": p, "category": "network", "attack_type": "smb",
                                 "service": "SMB", "priority": "CRITICAL"})

    # SSH
    if 22 in port_map:
        suggestions.append({"port": 22, "category": "network", "attack_type": "ssh",
                             "service": "SSH", "priority": "HIGH"})

    # FTP
    if 21 in port_map:
        suggestions.append({"port": 21, "category": "network", "attack_type": "ftp",
                             "service": "FTP", "priority": "HIGH"})

    # RDP
    if 3389 in port_map:
        suggestions.append({"port": 3389, "category": "network", "attack_type": "rdp",
                             "service": "RDP", "priority": "CRITICAL"})

    # Databases
    for p, svc in [(3306, "MySQL"), (5432, "PostgreSQL"), (1433, "MSSQL"),
                   (1521, "Oracle"), (6379, "Redis"), (27017, "MongoDB"),
                   (9200, "Elasticsearch")]:
        if p in port_map:
            suggestions.append({"port": p, "category": "network", "attack_type": "database",
                                 "service": svc, "priority": "CRITICAL"})

    # Docker
    if 2375 in port_map:
        suggestions.append({"port": 2375, "category": "network", "attack_type": "generic",
                             "service": "Docker (unauthenticated)", "priority": "CRITICAL"})

    return suggestions
