from langchain_openai import ChatOpenAI
import json
import tqdm

llm = ChatOpenAI(model="gpt-5.2", temperature=0) # gpt-4o-mini, gpt-5.2

with open("llm_queries.json") as f, open("llm_responses.json", "w+") as out:
    for line in tqdm.tqdm(f):
        j = json.loads(line)
        response = llm.invoke(j["prompt"])
        try:
            resp = response.content
            resp = resp.strip("```").strip("json")
            j["response"] = json.loads(resp)
            out.write(json.dumps(j) + "\n")
        except ValueError as e:
            print("Invalid JSON received")
            print(response.content)
            print(e)
