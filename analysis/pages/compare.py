import random
from typing import Tuple
import pandas as pd
import streamlit as st
import plotly.express as px
from BTrees.OOBTree import OOBTree


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

def add_entry(tree: OOBTree, entry: Tuple[int, int, str]):
    left = predecessor(tree, entry[0])
    left = (left, tree[left][0]) if left else None
    right = successor(tree, entry[0])
    right = (right, tree[right][0]) if right else None

    if left and left[1] > entry[0]: 
        entry = (left[1], entry[1], entry[2])
        right = successor(tree, entry[0])
        right = (right, tree[right][0]) if right else None

    if (entry[0] - entry[1]) > -0.0001:
        return

    if right and right[0] < entry[1]:
        next = (right[0], entry[1], entry[2])
        entry = (entry[0], right[0], entry[2])
        add_entry(tree, next)

    if (entry[0] - entry[1]) > -0.0001:
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
    st.session_state.data = px.data.gapminder().query("continent=='Oceania'")
    st.session_state.plot_key = "line_chart" + f"{random.randint(0, int(1e6))}"
    st.session_state.selection = None
    st.session_state.reset_plot = False
    st.session_state.tree = OOBTree()

st.session_state.compare_init = True

col1, col2, _ = st.columns([0.23, 0.23, 0.54])
with col1:
    if st.button("compare selection", type="primary"):
        st.session_state.reset_plot = True
        if st.session_state.selection is not None: 
            entry = (st.session_state.selection["x0"], st.session_state.selection["x1"], "compare")
            add_entry(st.session_state.tree, entry)
            # st.session_state.compare.append(st.session_state.selection)
    
with col2:
    if st.button("baseline selection"):
        st.session_state.reset_plot = True
        if st.session_state.selection is not None: 
            entry = (st.session_state.selection["x0"], st.session_state.selection["x1"], "baseline")
            add_entry(st.session_state.tree, entry)

if st.session_state.reset_plot:
    st.session_state.plot_key = "line_chart" + f"{random.randint(0, int(1e6))}"
    st.session_state.reset_plot = False

if st.session_state.data is not None:
    fig = px.line(st.session_state.data, x="year", y="lifeExp", markers=True)
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

if st.session_state.tree is not None: 
    tree = st.session_state.tree
    range_entries = pd.DataFrame({'start': pd.Series(dtype='int'), 'end': pd.Series(dtype='int'), 'range_type': pd.Series(dtype='str')})
    for elem in tree:
        start, end, range_type = elem, tree[elem][0], tree[elem][1]
        row = pd.DataFrame([[start, end, range_type]], columns=range_entries.columns)
        range_entries = pd.concat([range_entries, row], ignore_index=True)

    st.data_editor(range_entries, key="edited_rows", num_rows="dynamic")
    if st.session_state.edited_rows["deleted_rows"]:
        for idx in st.session_state.edited_rows["deleted_rows"]:
            start = range_entries.loc[idx]["start"]
            del tree[start]
        st.session_state.edited_rows["deleted_rows"] = []
        st.rerun()

    if st.session_state.edited_rows["edited_rows"]:
        for rowidx, changes in st.session_state.edited_rows["edited_rows"].items():
            row = range_entries.loc[rowidx, :].copy()
            del tree[row["start"]]
            for column, value in changes.items():
                row[column] = value
            add_entry(tree, (row["start"], row["end"], row["range_type"]))
        st.session_state.edited_rows["edited_rows"] = {}
        st.rerun()

    if st.session_state.edited_rows["added_rows"]:
        delete_rows = []
        for idx, row in enumerate(st.session_state.edited_rows["added_rows"]):
            if all(column in row for column in ["start", "end", "range_type"]):
                add_entry(tree, (row["start"], row["end"], row["range_type"]))
                delete_rows.append(idx)

        if delete_rows:
            for idx in delete_rows:
                st.session_state.edited_rows["added_rows"].pop(idx)
            st.rerun()
