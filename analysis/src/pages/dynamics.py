import streamlit as st
import pandas as pd
from src.components.thread_dynamics import thread_dynamics

st.set_page_config(page_title="Thread Dynamics", layout="wide")

# Load and parse the CSV
df = pd.read_csv("data.csv")

# Convert to a node/edge structure the frontend can consume
nodes = list(set(df["from"].tolist() + df["to"].tolist()))
edges = df.rename(columns={"from": "source", "to": "target"}).to_dict(orient="records")

graph_data = {"nodes": nodes, "edges": edges}

result = thread_dynamics(graph_data)
