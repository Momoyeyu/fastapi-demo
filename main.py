from fastapi import FastAPI

# init FastAPI app
app = FastAPI(
    title="FastAPI + UV Project",
    description="A FastAPI demo initialized by UV",
    version="1.0.0"
)

# route
@app.get("/")
async def root():
    return {"message": "Hello FastAPI + UV!"}
