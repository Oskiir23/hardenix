"""Cliente para un LLM local compatible con la API de OpenAI (LM Studio,
Ollama con /v1, etc.). Usa solo la librería estándar (urllib) — sin pip.

Genera explicaciones en español de los hallazgos de la auditoría. Todo el
procesamiento ocurre en local: nada se envía a la nube.
"""

import json
import re
import urllib.error
import urllib.request

# Algunos modelos (sobre todo de código) cuelan caracteres CJK sueltos.
# Los eliminamos para garantizar una salida limpia en español.
_CJK = re.compile(
    r"[　-〿぀-ヿ㐀-䶿一-鿿豈-﫿＀-￯]+"
)


def _clean(text):
    text = _CJK.sub("", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()

DEFAULT_URL = "http://localhost:1234/v1"

SYSTEM_PROMPT = (
    "Eres un experto en ciberseguridad y administración de sistemas Linux. "
    "Explica de forma clara, breve y profesional (3-4 frases, en español, sin "
    "markdown ni viñetas) un hallazgo de una auditoría de endurecimiento: qué "
    "significa, por qué es importante y qué riesgo real implica si no se corrige. "
    "Responde exclusivamente en español, sin usar caracteres de otros alfabetos."
)


class AIClient:
    def __init__(self, base_url=DEFAULT_URL, model=None, timeout=90):
        self.base = (base_url or DEFAULT_URL).rstrip("/")
        self.model = model
        self.timeout = timeout
        self.last_error = None

    def _get(self, path, timeout=None):
        req = urllib.request.Request(self.base + path)
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def _post(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def available(self):
        """Comprueba que el servidor responde y fija un modelo si no se indicó."""
        try:
            data = self._get("/models", timeout=5)
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.last_error = str(getattr(e, "reason", e))
            return False
        if self.model is None:
            items = data.get("data") or []
            if items:
                self.model = items[0].get("id")
        return True

    def _build_prompt(self, finding):
        lines = [f"Hallazgo: {finding.title}", f"Severidad: {finding.severity.label}"]
        if finding.current:
            lines.append(f"Estado actual: {finding.current}")
        if finding.expected:
            lines.append(f"Estado recomendado: {finding.expected}")
        if finding.detail:
            lines.append(f"Nota: {finding.detail}")
        return "\n".join(lines)

    def explain(self, finding):
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": self._build_prompt(finding)},
            ],
            "temperature": 0.3,
            "max_tokens": 240,
            "stream": False,
        }
        resp = self._post("/chat/completions", payload)
        return _clean(resp["choices"][0]["message"]["content"])
