import streamlit as st
import matplotlib
import matplotlib.pyplot as plt

from components.monaco_sql_editor import monaco_sql_editor
from database import DatabaseClient

db = DatabaseClient("../data/prism-2025-11-24T13:39:54.191391355+00:00.db3")

st.set_page_config(page_title="Debug", layout="wide")
st.title("Debug")
st.markdown("""
    This page allows you to execute custom SQL queries against the database.
    Use the editor below to write and test your queries.
""")

if "init" not in st.session_state:
    st.session_state.query_result = None
    st.session_state.line_chart_axis = None
    st.session_state.show_line_chart = False
    st.session_state.query = None

st.session_state.init = True

st.session_state.query = monaco_sql_editor(
    value=st.session_state.query if st.session_state.query is not None else "SELECT ts, pid, tid, run_share FROM taskstats_view ORDER BY ts LIMIT 100;",
    # schema=schema,
    height="150px",
    theme="vs-dark",
    key="sql_editor",
)

if st.button("Run Query"):
    st.session_state.query_result = db.custom_query(st.session_state.query)
    st.session_state.show_line_chart = False

if st.session_state.query_result is not None:
    st.write(st.session_state.query_result)

    with st.container():
        config_col1, config_col2, _ = st.columns([0.15, 0.15, 0.7])
        with config_col1:
            x_axis = st.selectbox(
                "X axis",
                st.session_state.query_result.columns,
                index=None,
                key="line_x_axis",
            )
        with config_col2:
            y_axis = st.selectbox(
                "Y axis",
                st.session_state.query_result.columns,
                index=None,
                key="line_y_axis",
            )

        if st.button("Create Line Graphs", type="primary"):
            st.session_state.show_line_chart = True
            st.session_state.line_chart_axis = {"x_axis": x_axis, "y_axis": y_axis}

if st.session_state.show_line_chart and st.session_state.query_result is not None:
    if st.session_state.line_chart_axis is not None:
        df = st.session_state.query_result.copy()
        x_axis = st.session_state.line_chart_axis["x_axis"]
        y_axis = st.session_state.line_chart_axis["y_axis"]

        fig = plt.figure(figsize=(12, 8))

        label_columns = df.columns.difference([x_axis, y_axis])
        for _, label in df.loc[:, label_columns].drop_duplicates().iterrows():
            filtered = df
            for col, val in zip(label_columns, label):
                filtered = filtered.loc[filtered[col] == val]
            plt.plot(filtered[x_axis], filtered[y_axis])
        st.pyplot(fig, width=800)
        plt.close()
