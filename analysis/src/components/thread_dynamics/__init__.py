import streamlit as st

out = st.components.v2.component(
    "src.thread_dynamics",
    js="index-*.js",
    html='<div class="react-root"></div>',
)

def thread_dynamics(graph_data, key=None):
    component_value = out(
        key=key,
        default={},
        data={"graph_data": graph_data},
        height=900,
        width=1600,
    )
    return component_value
