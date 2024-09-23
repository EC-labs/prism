from fastapi import FastAPI
from model import emotion_analyzer

app = FastAPI()

@app.get("/")
def root(query: str):
    prediction = emotion_analyzer.predict(query)
    return prediction.probas
