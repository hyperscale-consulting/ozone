def rule(id: str, reason: str) -> dict:
    return {"id": id, "reason": reason}


def suppress(rules_to_suppress: list) -> dict:
    return {"cfn_nag": {"rules_to_suppress": rules_to_suppress}}
