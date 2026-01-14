"""
Monaco SQL Editor Custom Streamlit Component

A custom Streamlit component that provides Monaco Editor with SQL autocomplete
based on the actual database schema (tables and columns).
"""

import os

import streamlit.components.v1 as components

# Create a _RELEASE variable to toggle between development and production
component_path = os.getenv("SQL_EDITOR") or "frontend/build"
_component_func = components.declare_component("monaco_sql_editor", path=component_path)


def monaco_sql_editor(
    value: str = "",
    schema: dict | None = None,
    height: str = "600px",
    theme: str = "vs-dark",
    key: str = "",
):
    """
    Create a Monaco SQL Editor with database schema autocomplete.

    Parameters
    ----------
    value : str
        The initial SQL query to display in the editor.
    schema : dict
        Database schema containing tables and columns.
        Format: {"tables": ["table1", "table2"], "columns": {"table1": ["col1", "col2"]}}
    height : str
        Height of the editor (default: "300px")
    theme : str
        Monaco theme to use (default: "vs-dark", options: "vs", "vs-dark", "hc-black")
    key : str
        Unique key for the component instance

    Returns
    -------
    str
        The current content of the editor
    """
    if schema is None:
        schema = {"tables": [], "columns": {}, "keywords": []}

    component_value = _component_func(
        value=value,
        schema=schema,
        height=height,
        theme=theme,
        key=key,
        default=value,
    )

    return component_value


__all__ = ["monaco_sql_editor"]
