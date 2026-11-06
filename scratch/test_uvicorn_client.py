import uvicorn
from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/")
def get_client(request: Request):
    return {"client": request.client.host if request.client else None}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001, forwarded_allow_ips="*")
