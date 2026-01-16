import tempfile
import streamlit as st

from src.database import DatabaseClient

def main():
    st.title('Performance Analysis')
    st.set_page_config(page_title="Ripple", layout="centered")

    if 'main_init' not in st.session_state:
        st.session_state.db = None

    st.session_state.main_init = True

    database = st.file_uploader("Upload Database File", type=["db3"])
    if database:
        tmp = tempfile.NamedTemporaryFile(delete=True, delete_on_close=True)
        tmp.write(database.read())
        st.session_state.db_file = tmp
        st.session_state.db = DatabaseClient(tmp.name)

    if st.session_state.db is not None:
        st.success("Connected to database successfully", icon="✅")
        st.markdown("Navigate to the other pages:")
        st.page_link("pages/ripple.py", label="Ripple", icon="🌐")
        st.page_link("pages/kpi.py", label="KPI", icon="📉")

if __name__ == "__main__":
    main()
