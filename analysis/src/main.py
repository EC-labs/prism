import streamlit as st

def main():
    pages = [
        st.Page("pages/home.py", title="Home"),
        st.Page("pages/kpi.py", title="KPI"),
        st.Page("pages/ripple.py", title="Ripple"),
        st.Page("pages/debug.py", title="Debug"),
        st.Page("pages/dynamics.py", title="Dynamics"),
    ]

    pg = st.navigation(pages)
    pg.run()


if __name__ == "__main__":
    main()
