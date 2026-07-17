import requests
import json
import os
import tqdm
import re
import time

model = "qwen/qwen3-32b" # "openai/gpt-5.2", "openai/gpt-5.5", "qwen/qwen3-235b-a22b", "qwen/qwen3-32b", "google/gemini-2.5-pro", "anthropic/claude-sonnet-4.6", "meta-llama/llama-4-maverick", "mistralai/ministral-3b-2512"
remove_technique_identifiers = True # removes mitre attack info from log lines to avoid biasing the LLM

response_format = {
    "type": "json_schema",
    "json_schema": {
        "name": "mitre_response",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "techniques": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "confidence": {
                    "type": "string"
                },
                "explanation": {
                    "type": "string"
                }
            },
            "required": [
                "techniques",
                "confidence",
                "explanation"
            ],
            "additionalProperties": False
        }
    }
}

resp = requests.get("https://openrouter.ai/api/v1/models")
resp.raise_for_status()
model_list = resp.json()["data"]
model_canonical_slug = "Unknown"
for model_info in model_list:
    if model_info["id"] == model:
        model_canonical_slug = model_info["canonical_slug"]
        break
else:
    print(f"Model not found: {model}")

url = "https://openrouter.ai/api/v1/chat/completions"
headers = {
      "Authorization": f"Bearer {os.environ.get('OPENROUTER_API_KEY')}",
      "Content-Type": "application/json"
}

technique_pattern = r"T\d{4}"

with open("llm_queries.json") as f, open("llm_responses.json", "w+") as out:
    for line in tqdm.tqdm(f):
        j = json.loads(line)
        if remove_technique_identifiers:
            # in audit
            j["prompt"] = re.sub(r'\s*key="[^"]*"', '', j["prompt"]) # in audit
            # in alerts
            j["prompt"] = re.sub(r'\s*key=\\"[^"]*\\"', '', j["prompt"])
            j["prompt"] = re.sub(r'\s*"key"\s*:\s*"[^"]*"', '', j["prompt"])
            j["prompt"] = re.sub(r',?\s*"mitre_tactic_id"\s*:\s*\[[^\]]*\]', '', j["prompt"])
            j["prompt"] = re.sub(r',?\s*"mitre_tactic_name"\s*:\s*\[[^\]]*\]', '', j["prompt"])
            j["prompt"] = re.sub(r',?\s*"mitre_technique_id"\s*:\s*\[[^\]]*\]', '', j["prompt"])
            j["prompt"] = re.sub(r',?\s*"mitre_technique_name"\s*:\s*\[[^\]]*\]', '', j["prompt"])
            j["prompt"] = re.sub(r',?\s*"mitre"\s*:\s*\{[^{}]*\}', '', j["prompt"])
        if re.search(technique_pattern, j["prompt"]):
            print("Found MITRE identifiers: " + str(re.findall(technique_pattern, j["prompt"])))
            print(j["prompt"])
        payload = {"model": model, "messages": [{"role": "user", "content": j["prompt"]}], "temperature": 0, "reasoning": {"effort": "minimal", "exclude": True}, "response_format": response_format}
        #if model == "qwen/qwen3-235b-a22b":
        #    del payload["response_format"]
        #    del payload["reasoning"]
        #    payload["max_tokens"] = 512
        max_retries = 5
        for attempt in range(max_retries):
            try:
                response = requests.post(url, headers=headers, json=payload)
                response.raise_for_status()
                resp = response.json()["choices"][0]["message"]["content"]
                j["response"] = json.loads(resp)
                j["canonical_slug"] = model_canonical_slug
                out.write(json.dumps(j) + "\n")
                out.flush()
                break
            except Exception as e:
                print(f"Error on attempt {attempt + 1}/{max_retries}")
                print(e)
                try:
                    print(response.content)
                except NameError:
                    pass
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    print("Giving up on this query")
