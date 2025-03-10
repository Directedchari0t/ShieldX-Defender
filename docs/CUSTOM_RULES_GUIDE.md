
---

### **CUSTOM_RULES_GUIDE.md**

```markdown
# Custom YARA Rules Guide

## Rule Basics
YARA rules follow this structure:
```yara
rule RuleName {
    meta:
        description = "Rule description"
        author = "Your Name"
        date = "2023-08-20"

    strings:
        $suspicious_string = "malicious-pattern"
        $hex_pattern = { E2 34 A1 D8 }

    condition:
        any of them
}



Place your custom rules in:-------------------|
                                              |
                                              |
                                              |
                                              V
data/yara_rules/
├── exploits.yar
├── ransomware.yar
└── custom_rules.yar  <-- Add new rules here
