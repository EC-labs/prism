"""
Debugging Database Client

Simplified database client focused on debugging and ad-hoc queries.
Provides core DuckDB connectivity without application-specific logic.
"""

import duckdb

from pathlib import Path

SQL_DIR = Path(__file__).parent / "sql"

class DatabaseClient:
    """Lightweight database client for debugging purposes."""

    def __init__(self, uri: str):
        """Initialize the debugging database client."""
        self.conn = duckdb.connect(database=uri)
        ddl = (SQL_DIR / "ddl.sql").read_text()
        self.conn.execute(ddl)

    def custom_query(self, query: str):
        """
        Execute a custom SQL query and return results as a DataFrame.

        Args:
            query: SQL query string to execute

        Returns:
            pandas.DataFrame: Query results
        """
        return self.conn.execute(query).df()

    def get_all_tables(self):
        """
        Get list of all tables in the database.

        Returns:
            pandas.DataFrame: Table names and schema information
        """
        query = """
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
        ORDER BY table_schema, table_name
        """
        return self.conn.execute(query).df()

    def get_all_columns(self):
        """
        Get list of all columns across all tables.

        Returns:
            pandas.DataFrame: Column information with table context
        """
        query = """
        SELECT
            table_schema,
            table_name,
            column_name,
            data_type,
            is_nullable
        FROM information_schema.columns
        WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
        ORDER BY table_schema, table_name, ordinal_position
        """
        return self.conn.execute(query).df()

    def get_table_schema(self, table_name):
        """
        Get detailed schema information for a specific table.

        Args:
            table_name: Name of the table to describe

        Returns:
            pandas.DataFrame: Column details for the specified table
        """
        query = f"DESCRIBE {table_name}"
        return self.conn.execute(query).df()

    def get_table_preview(self, table_name, limit=10):
        """
        Get a preview of rows from a table.

        Args:
            table_name: Name of the table to preview
            limit: Number of rows to return (default: 10)

        Returns:
            pandas.DataFrame: Sample rows from the table
        """
        query = f"SELECT * FROM {table_name} LIMIT {limit}"
        return self.conn.execute(query).df()

    def get_database_schema(self):
        """
        Get database schema formatted for Monaco Editor autocomplete.

        Returns:
            dict: Schema with tables list, columns dictionary, and SQL keywords
                  Format: {
                      "tables": ["table1", ...],
                      "columns": {"table1": ["col1", ...]},
                      "keywords": ["SELECT", "FROM", ...]
                  }
        """
        # Get all tables
        tables_df = self.get_all_tables()
        tables = tables_df["table_name"].unique().tolist()

        # Get all columns grouped by table
        columns_df = self.get_all_columns()
        columns = {}
        for table in tables:
            table_columns = columns_df[columns_df["table_name"] == table][
                "column_name"
            ].tolist()
            columns[table] = table_columns

        # Get all DuckDB keywords
        keywords_query = "SELECT keyword_name FROM duckdb_keywords() ORDER BY keyword_name"
        keywords_df = self.conn.execute(keywords_query).df()
        keywords = keywords_df["keyword_name"].tolist()

        return {"tables": tables, "columns": columns, "keywords": keywords}

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
