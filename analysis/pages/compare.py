from pathlib import Path
import random
from typing import Tuple
import pandas as pd
import streamlit as st
import plotly.express as px
from BTrees.OOBTree import OOBTree


def generate_edited_key() -> str:
    return f"edited_rows{random.randint(0, int(1e6))}"

def predecessor(t: OOBTree, x):
    try:
        return t.maxKey(x)  # keys < x
    except ValueError:
        return None

def successor(t: OOBTree, x):
    try:
        return t.minKey(x)  # keys < x
    except ValueError:
        return None

def add_entry(tree: OOBTree, entry: Tuple[pd.Timestamp, pd.Timestamp, str]):
    left = predecessor(tree, entry[0])
    left = (left, tree[left][0]) if left else None
    right = successor(tree, entry[0])
    right = (right, tree[right][0]) if right else None

    if left and left[1] > entry[0]: 
        entry = (left[1], entry[1], entry[2])
        right = successor(tree, entry[0])
        right = (right, tree[right][0]) if right else None

    if (entry[0] - entry[1]) >= pd.Timedelta(-0.0001):
        return

    if right and right[0] < entry[1]:
        next = (right[0], entry[1], entry[2])
        entry = (entry[0], right[0], entry[2])
        add_entry(tree, next)

    if (entry[0] - entry[1]) >= pd.Timedelta(-0.0001):
        return

    tree[entry[0]] = (entry[1], entry[2])

st.set_page_config(page_title="Compare", layout="centered")
st.markdown("""
    # Compare and Baseline Selection

    Through this page, you can specify the ranges that belong to the baseline and 
    compare periods. 

    For example, if you'd like to understand why an application degraded at a
    particular moment in time, then the baseline period would be the range during
    which the application was performing well, and compare is the range during
    which its performance was degraded.
""")

if 'compare_init' not in st.session_state:
    st.session_state.target_data = None
    st.session_state.plot_key = "line_chart" + f"{random.randint(0, int(1e6))}"
    st.session_state.selection = None
    st.session_state.reset_plot = False
    st.session_state.tree = OOBTree()
    st.session_state.compare_chart_axis = None
    st.session_state.edited_rows_key = generate_edited_key()

st.session_state.compare_init = True

target_file = st.file_uploader("Upload Target Metric", type=["csv", "xlsx"])
if target_file:
    path = Path(target_file.name)
    st.session_state.target_data = pd.read_excel(target_file) if path.suffix == ".xlsx" else pd.read_csv(target_file)

if st.session_state.target_data is not None:
    with st.container():
        config_col1, config_col2, _ = st.columns([0.3, 0.3, 0.4])
        target_columns = st.session_state.target_data.columns
        with config_col1:
            x_index = (None if not st.session_state.compare_chart_axis 
                       else target_columns.get_loc(st.session_state.compare_chart_axis["x_axis"]))
            x_axis = st.selectbox(
                "Time",
                target_columns,
                index=x_index,
                key="target_x",
            )
        with config_col2:
            y_index = (None if not st.session_state.compare_chart_axis 
                       else target_columns.get_loc(st.session_state.compare_chart_axis["y_axis"]))
            y_axis = st.selectbox(
                "Target Metric",
                target_columns,
                index=y_index,
                key="target_y",
            )

        if x_axis and y_axis:
            st.session_state.compare_chart_axis = {"x_axis": x_axis, "y_axis": y_axis}


if st.session_state.reset_plot:
    st.session_state.plot_key = "line_chart" + f"{random.randint(0, int(1e6))}"
    st.session_state.reset_plot = False

def main():
    if (st.session_state.target_data is None) or (not st.session_state.compare_chart_axis):
        return

    with st.container(border=True):
            col1, col2, _ = st.columns([0.25, 0.25, 0.5])
            with col1:
                if st.button("compare selection", type="primary"):
                    st.session_state.reset_plot = True
                    if st.session_state.selection is not None: 
                        entry = (pd.to_datetime(st.session_state.selection["x0"]), pd.to_datetime(st.session_state.selection["x1"]), "compare")
                        add_entry(st.session_state.tree, entry)
                
            with col2:
                if st.button("baseline selection"):
                    st.session_state.reset_plot = True
                    if st.session_state.selection is not None: 
                        entry = (pd.to_datetime(st.session_state.selection["x0"]), pd.to_datetime(st.session_state.selection["x1"]), "baseline")
                        add_entry(st.session_state.tree, entry)

            fig = px.line(st.session_state.target_data, x=st.session_state.compare_chart_axis["x_axis"], y=st.session_state.compare_chart_axis["y_axis"], markers=True)
            tree = st.session_state.tree
            for elem in tree:
                fig.add_vrect(x0=elem, x1=tree[elem][0], line_width=0, fillcolor="green" if tree[elem][1] == "baseline" else "red", opacity=0.2)

            fig.update_layout(dragmode='select', selectdirection="h")

            events = st.plotly_chart(
                fig,
                on_select='rerun',
                key=st.session_state.plot_key,
            )
            if events and 'selection' in events:
                selection = events["selection"]
                box = selection.get("box")
                if box: 
                    x = box[0]["x"]
                    x0, x1 = x[0], x[1]
                    x0, x1 = (x0, x1) if x0 <= x1 else (x1, x0)
                    st.session_state.selection = {"x0": x0, "x1": x1}

    if len(st.session_state.tree): 
        tree = st.session_state.tree
        range_entries = pd.DataFrame({'start': pd.Series(dtype='datetime64[ns]'), 'end': pd.Series(dtype='datetime64[ns]'), 'range_type': pd.Series(dtype='str')})
        for elem in tree:
            start, end, range_type = elem, tree[elem][0], tree[elem][1]
            row = pd.DataFrame([[start, end, range_type]], columns=range_entries.columns)
            range_entries = pd.concat([range_entries, row], ignore_index=True)

        st.data_editor(range_entries, key=st.session_state.edited_rows_key, num_rows="dynamic")
        edited_rows = st.session_state[st.session_state.edited_rows_key]
        if edited_rows["deleted_rows"]:
            for idx in edited_rows["deleted_rows"]:
                start = range_entries.loc[idx]["start"]
                del tree[start]
            st.session_state.edited_rows_key = generate_edited_key()
            st.rerun()

        if edited_rows["edited_rows"]:
            for rowidx, changes in edited_rows["edited_rows"].items():
                row = range_entries.loc[rowidx, :].copy()
                del tree[row["start"]]
                for column, value in changes.items():
                    row[column] = value
                add_entry(tree, (pd.to_datetime(row["start"]), pd.to_datetime(row["end"]), row["range_type"]))
            st.session_state.edited_rows_key = generate_edited_key()
            st.rerun()

        if edited_rows["added_rows"]:
            delete_rows = []
            for idx, row in enumerate(edited_rows["added_rows"]):
                if all(column in row for column in ["start", "end", "range_type"]):
                    add_entry(tree, (pd.to_datetime(row["start"]), pd.to_datetime(row["end"]), row["range_type"]))
                    delete_rows.append(idx)

            if delete_rows:
                st.session_state.edited_rows_key = generate_edited_key()
                st.rerun()

main()
