"""Serialize successful form controls, preserving tokens and all unmodified values."""

from urllib.parse import urlencode


def probe_forms(form):
    """Yield (field name, control, baseline values) only for editable non-secret fields."""
    if form.get("enctype", "application/x-www-form-urlencoded").lower() != "application/x-www-form-urlencoded":
        return
    if form.get("method", "get").lower() not in {"get", "post"}:
        return
    if form.find(attrs={"name": lambda name: name and name.lower() in {"_method", "http_method", "x-http-method-override"}}):
        return  # Framework method overrides need a separate effective-method contract.
    controls = []
    for field in form.find_all(["input", "textarea", "select"]):
        name = field.get("name")
        kind = field.get("type", "text").lower()
        if not name or field.has_attr("disabled") or field.find_parent("fieldset", disabled=True):
            continue
        if kind in {"submit", "image", "button", "reset", "file"}:
            continue
        if kind in {"checkbox", "radio"} and not field.has_attr("checked"):
            continue
        if field.name == "select":
            options = [option for option in field.find_all("option") if not option.has_attr("disabled")]
            selected = [option for option in options if option.has_attr("selected")]
            selected = selected if field.has_attr("multiple") else (selected or options)[:1]
            values = [option.get("value", option.get_text()) for option in selected]
        elif field.name == "textarea":
            values = [field.get_text()]
        else:
            values = [field.get("value", "on" if kind in {"checkbox", "radio"} else "")]
        for value in values:
            controls.append((name, value, field))
    baseline = [(name, value) for name, value, _ in controls]
    for index, (name, _, field) in enumerate(controls):
        kind = field.get("type", "text").lower()
        if field.name not in {"input", "textarea"} or kind not in {"text", "search", "url", "tel", "email", "number"}:
            continue
        if any(token in name.lower() for token in ("csrf", "xsrf", "token", "authenticity", "verification", "password")):
            continue
        yield name, index, baseline


async def submit_probe(client, method, url, baseline, index, payload):
    values = list(baseline)
    values[index] = (values[index][0], payload)
    encoded = urlencode(values)
    if method == "post":
        return await client.post(url, content=encoded, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=5)
    return await client.get(url, params=values, timeout=5)
