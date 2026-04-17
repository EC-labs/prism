import streamlit as st

out = st.components.v2.component(
    "src.thread_dynamics",
    js="index-*.js",
    html='<div class="react-root"></div>',
)

def thread_dynamics(graph_data, on_request_cb, key=None):
    component_state = st.session_state.get(key, {})
    response = component_state.get("response")
    data = {"graph_data": graph_data, "response": response}
    component_value = out(
        key=key,
        default={},
        data=data,
        height=900,
        width=1600,
        on_request_change=on_request_cb,
        on_response_change=lambda: None,
    )
    return component_value
