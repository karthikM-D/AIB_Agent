import ollama, json, time
t=time.time()
r=ollama.chat(model="llama3.1:8b-instruct-q4_K_M",
  messages=[{"role":"user","content":"Alert: 15 failed SSH logins from 203.0.113.9 to dev-box-02 in 2 min, then 1 success. Return JSON with keys verdict (benign|suspicious|malicious) and reason."}],
  format="json", options={"temperature":0.2,"seed":42})
print(round(time.time()-t,1),"s"); print(r["message"]["content"])
