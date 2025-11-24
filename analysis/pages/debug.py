import streamlit as st
import pandas as pd
from streamlit_monaco import st_monaco
import pandas as pd
import streamlit as st
from numpy.random import default_rng as rng

from components.monaco_sql_editor import monaco_sql_editor
from database import DatabaseClient

db = DatabaseClient("../data/prism-2025-11-21T11:46:41.944295953+00:00.db3")

st.set_page_config(page_title="Debug", layout="wide")
st.title("Debug")
st.markdown(
    """
    This page allows you to execute custom SQL queries against the database.
    Use the editor below to write and test your queries.
"""
)

if "init" not in st.session_state:
    st.session_state.query_result = None
    st.session_state.line_chart_axis = None
    st.session_state.show_line_chart = False

st.session_state.init = True

content = monaco_sql_editor(
    value="SELECT * FROM taskstats_view LIMIT 10;",
    # schema=schema,
    height="150px",
    theme="vs-dark",
    key="sql_editor",
)

if st.button("Run Query"):
    print(content)
    st.session_state.query_result = db.custom_query(content)


if st.session_state.query_result is not None:
    st.write(st.session_state.query_result)

    with st.container():
        config_col1, config_col2 = st.columns(2)
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
            print("show line chart", st.session_state.show_line_chart)
            st.session_state.line_chart_axis = {"x_axis": x_axis, "y_axis": y_axis}

if st.session_state.show_line_chart == True:
    if st.session_state.line_chart_axis is not None:
        st.line_chart(st.session_state.query_result, x=st.session_state.line_chart_axis["x_axis"], 
                      y=st.session_state.line_chart_axis["y_axis"])


# content = st_monaco(value="# Hello world", height="600px", language="markdown")

# if st.button("Show editor's content"):
#     st.write(content)


