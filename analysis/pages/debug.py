import streamlit as st
import numpy as np
import matplotlib.pyplot as plt

from components.monaco_sql_editor import monaco_sql_editor

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

def bar_tab(tab):
    if st.session_state.query_result is None:
        return

    data = st.session_state.query_result

    with tab.container():
        config_col1, config_col2, config_col3, _ = st.columns([0.15, 0.15, 0.05, 0.65])
        with config_col1:
            x_axis = st.selectbox(
                "X Axis",
                st.session_state.query_result.columns,
                index=None,
            )

        with config_col2:
            y_axis = st.selectbox(
                "Y Axis",
                st.session_state.query_result.columns,
                index=None,
            )

    if (x_axis is None) or (y_axis is None):
        return

    fig = plt.figure(figsize=(12, 8))
    label_columns = data.columns.difference([x_axis, y_axis])
    for _, label in data.loc[:, label_columns].drop_duplicates().iterrows():
        filtered = data
        for col, val in zip(label_columns, label):
            filtered = filtered.loc[filtered[col] == val]
        label = "-".join(label.astype(str))
        plt.bar(filtered[x_axis], filtered[y_axis], alpha=0.4, label=label)
    plt.legend()
    tab.pyplot(fig, width=800)
    plt.close()


def histogram_tab(tab):
    if st.session_state.query_result is None:
        return

    with tab.container():
        config_col1, config_col2, config_col3, _ = st.columns([0.15, 0.15, 0.05, 0.65])
        with config_col1:
            distribution = st.selectbox(
                "Distribution",
                st.session_state.query_result.columns,
                index=None,
            )

        with config_col2:
            group_by = st.selectbox(
                "Group By",
                st.session_state.query_result.columns,
                index=None,
            )

        with config_col3:
            n_bins = st.number_input("# Bins", value=20)

    with tab.container():
        config_col1, config_col2, _ = st.columns([0.05, 0.05, 0.9])
        with config_col1:
            range_min = st.number_input("Range Min", value=0.0)
        with config_col2:
            range_max = st.number_input("Range Max", value=1.0)

    if distribution not in st.session_state.query_result.columns:
        return

    if group_by is None:
        data = st.session_state.query_result[distribution].dropna()
        counts, bins = np.histogram(
            data,
            bins=n_bins,
            range=(range_min, range_max)
        )

        pmf = counts / counts.sum()

        fig = plt.figure(figsize=(12, 8))
        plt.bar(
            bins[:-1],
            pmf,
            width=np.diff(bins),
            align="edge",
            alpha=0.4,
        )

        plt.ylabel("Probability")
        plt.xlabel(distribution)
        plt.ylim(0, 1)

        tab.pyplot(fig, width=800)
        plt.close()
    elif group_by in st.session_state.query_result.columns:

        data = st.session_state.query_result
        fig = plt.figure(figsize=(12, 8))
        for group in data[group_by].unique():
            filtered = data.loc[data[group_by] == group, distribution]
            counts, bins = np.histogram(
                filtered,
                bins=n_bins,
                range=(range_min, range_max)
            )

            pmf = counts / counts.sum()

            plt.bar(
                bins[:-1],
                pmf,
                width=np.diff(bins),
                align="edge",
                alpha=0.4,
                label=group
            )

        plt.legend()
        plt.ylim(0, 1)
        tab.pyplot(fig, width=800)
        plt.close()

    # pmf = data.value_counts(normalize=True).sort_index()

    # fig = plt.figure(figsize=(12, 8))
    # plt.hist(st.session_state.query_result[distribution], bins=n_bins, density=True)
    # tab.pyplot(fig, width=800)
    # plt.close()



def line_tab(tab):
    if st.session_state.query_result is None:
        return

    with tab.container():
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

        if tab.button("Create Line Chart", type="primary", disabled=(x_axis is None or y_axis is None)) and x_axis and y_axis:
            st.session_state.show_line_chart = True
            st.session_state.line_chart_axis = {"x_axis": x_axis, "y_axis": y_axis}

    if (not st.session_state.show_line_chart) or (st.session_state.line_chart_axis is None):
        return

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
    tab.pyplot(fig, width=800)
    plt.close()

def main():
    if ('db' not in st.session_state) or (st.session_state.db is None):
        st.markdown(
            """
            <div style="
                padding: 1rem;
                border-radius: 0.5rem;
                background-color: rgba(0, 123, 255, 0.1);
                border-left: 0.25rem solid #0d6efd;
                color: inherit;
                ">
                You’re almost ready — connect to a Prism database
                <a href="/" target="_self" style="color: #0d6efd; text-decoration: underline;">
                    here
                </a>.
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    db = st.session_state.db

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

        line, histogram, bar = st.tabs(["line", "histogram", "bar"])
        line_tab(line)
        histogram_tab(histogram)
        bar_tab(bar)

main()
