import React, { useEffect, useRef, useState } from "react";
import Editor, { OnMount } from "@monaco-editor/react";
import { Streamlit } from "streamlit-component-lib";
import * as monaco from "monaco-editor";

interface Schema {
  tables: string[];
  columns: { [key: string]: string[] };
  keywords: string[];
}

// Comprehensive SQL functions list
const SQL_FUNCTIONS = [
  // Aggregate functions
  "COUNT",
  "SUM",
  "AVG",
  "MAX",
  "MIN",
  "STRING_AGG",
  "ARRAY_AGG",
  "STDDEV",
  "VARIANCE",
  "MEDIAN",
  "MODE",
  "QUANTILE",

  // String functions
  "CONCAT",
  "SUBSTRING",
  "SUBSTR",
  "TRIM",
  "LTRIM",
  "RTRIM",
  "UPPER",
  "LOWER",
  "LENGTH",
  "REPLACE",
  "SPLIT",
  "REGEXP_MATCHES",
  "REGEXP_REPLACE",
  "LIKE",
  "ILIKE",
  "LEFT",
  "RIGHT",
  "REVERSE",
  "REPEAT",
  "LPAD",
  "RPAD",
  "POSITION",
  "STRPOS",

  // Date/Time functions
  "NOW",
  "CURRENT_DATE",
  "CURRENT_TIME",
  "CURRENT_TIMESTAMP",
  "DATE_DIFF",
  "DATE_ADD",
  "DATE_SUB",
  "DATE_TRUNC",
  "DATE_PART",
  "EXTRACT",
  "EPOCH",
  "TO_TIMESTAMP",
  "STRFTIME",
  "STRPTIME",

  // Conditional functions
  "CASE",
  "WHEN",
  "THEN",
  "ELSE",
  "END",
  "COALESCE",
  "NULLIF",
  "IFNULL",
  "IF",

  // Window functions
  "ROW_NUMBER",
  "RANK",
  "DENSE_RANK",
  "PERCENT_RANK",
  "LEAD",
  "LAG",
  "FIRST_VALUE",
  "LAST_VALUE",
  "NTH_VALUE",
  "NTILE",
  "CUME_DIST",

  // Type conversion
  "CAST",
  "TRY_CAST",
  "TYPEOF",
  "TO_JSON",

  // Math functions
  "ABS",
  "CEIL",
  "CEILING",
  "FLOOR",
  "ROUND",
  "TRUNC",
  "EXP",
  "LN",
  "LOG",
  "LOG10",
  "SQRT",
  "POWER",
  "POW",
  "SIN",
  "COS",
  "TAN",
  "ASIN",
  "ACOS",
  "ATAN",
  "ATAN2",
  "DEGREES",
  "RADIANS",
  "PI",
  "RANDOM",

  // Array functions
  "ARRAY_LENGTH",
  "ARRAY_EXTRACT",
  "UNNEST",
  "LIST_VALUE",

  // JSON functions
  "JSON_EXTRACT",
  "JSON_EXTRACT_PATH",
];

interface MonacoSqlEditorProps {
  args: {
    value: string;
    schema: Schema;
    height: string;
    theme: string;
  };
}

const MonacoSqlEditor: React.FC<MonacoSqlEditorProps> = ({ args }) => {
  const { value, schema, height, theme } = args;
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);

  // State for resizable editor
  const [editorHeight, setEditorHeight] = useState<number>(parseInt(height) || 600);
  const [isResizing, setIsResizing] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Min and max height constraints
  const MIN_HEIGHT = 200;
  const MAX_HEIGHT = 1200;

  useEffect(() => {
    // Notify Streamlit when component is ready and set initial value
    Streamlit.setComponentValue(value);
    Streamlit.setFrameHeight();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Resize handler functions
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsResizing(true);
    e.preventDefault();
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing || !containerRef.current) return;

      const containerRect = containerRef.current.getBoundingClientRect();
      const newHeight = e.clientY - containerRect.top;

      // Apply min/max constraints
      const constrainedHeight = Math.max(MIN_HEIGHT, Math.min(MAX_HEIGHT, newHeight));
      setEditorHeight(constrainedHeight);

      // Update Streamlit frame height
      Streamlit.setFrameHeight();
    };

    const handleMouseUp = () => {
      if (isResizing) {
        setIsResizing(false);
      }
    };

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizing]);

  const handleEditorDidMount: OnMount = (editor, monacoInstance) => {
    editorRef.current = editor;

    // Configure editor to show more suggestions with better visibility
    editor.updateOptions({
      suggest: {
        filterGraceful: false, // Disable graceful filtering - show all matches
        localityBonus: true,
        shareSuggestSelections: false,
        preview: true, // Show preview of suggestions
      },
      fixedOverflowWidgets: true, // Render suggestion widgets in fixed overlay
      quickSuggestionsDelay: 0, // Show suggestions immediately
    });

    // Force suggest widget to show multiple items using MutationObserver
    const observer = new MutationObserver(() => {
      const suggestWidget = document.querySelector('.monaco-editor .suggest-widget');
      if (suggestWidget) {
        const listElement = suggestWidget.querySelector('.monaco-list') as HTMLElement;
        if (listElement && listElement.style.height === '18px') {
          // Monaco sets height to 18px for 1 item, force it to show 10 items (200px)
          listElement.style.height = '200px';
        }
      }
    });

    // Observe the document for changes
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style'],
    });

    // Register SQL completion provider with trigger characters
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const completionProvider =
      monacoInstance.languages.registerCompletionItemProvider("sql", {
        triggerCharacters: [" ", ".", ","],
        provideCompletionItems: (model, position) => {
          const textUntilPosition = model.getValueInRange({
            startLineNumber: position.lineNumber,
            startColumn: 1,
            endLineNumber: position.lineNumber,
            endColumn: position.column,
          });

          // Get the word being typed
          const word = model.getWordUntilPosition(position);
          const range = {
            startLineNumber: position.lineNumber,
            endLineNumber: position.lineNumber,
            startColumn: word.startColumn,
            endColumn: word.endColumn,
          };

          const suggestions: monaco.languages.CompletionItem[] = [];

          // Detect context for smart prioritization
          const afterFrom = /\b(FROM|JOIN|INTO|UPDATE|TABLE)\s+\w*$/i.test(
            textUntilPosition,
          );
          const afterSelect =
            /\b(SELECT|WHERE|ORDER BY|GROUP BY|HAVING|ON|AND|OR)\s+\w*$/i.test(
              textUntilPosition,
            );

          // ALWAYS add SQL keywords (400+ from DuckDB)
          if (schema.keywords && Array.isArray(schema.keywords)) {
            schema.keywords.forEach((keyword) => {
              suggestions.push({
                label: keyword,
                kind: monacoInstance.languages.CompletionItemKind.Keyword,
                detail: "Keyword",
                documentation: "SQL Keyword",
                insertText: keyword,
                range: range,
                sortText: "2_" + keyword.toLowerCase(),
              });
            });
          }

          // ALWAYS add SQL functions
          SQL_FUNCTIONS.forEach((func) => {
            suggestions.push({
              label: func,
              kind: monacoInstance.languages.CompletionItemKind.Function,
              detail: "Function",
              documentation: "SQL Function",
              insertText: func + "()",
              insertTextRules:
                monacoInstance.languages.CompletionItemInsertTextRule
                  .InsertAsSnippet,
              range: range,
              sortText: afterSelect
                ? "1_" + func.toLowerCase()
                : "3_" + func.toLowerCase(),
            });
          });

          // ALWAYS add all tables
          if (schema.tables && Array.isArray(schema.tables)) {
            schema.tables.forEach((table) => {
              suggestions.push({
                label: table,
                kind: monacoInstance.languages.CompletionItemKind.Class,
                detail: "Table",
                documentation: `Table: ${table}`,
                insertText: table,
                range: range,
                sortText: afterFrom
                  ? "0_" + table.toLowerCase()
                  : "4_" + table.toLowerCase(),
              });
            });
          }

          // ALWAYS add all columns from all tables
          if (schema.columns && typeof schema.columns === "object") {
            Object.entries(schema.columns).forEach(([table, columns]) => {
              if (Array.isArray(columns)) {
                columns.forEach((column) => {
                  suggestions.push({
                    label: column,
                    kind: monacoInstance.languages.CompletionItemKind.Field,
                    detail: `${table}`,
                    documentation: `Column from table: ${table}`,
                    insertText: column,
                    range: range,
                    sortText: afterSelect
                      ? "0_" + column.toLowerCase()
                      : "5_" + column.toLowerCase(),
                  });
                });
              }
            });
          }

          return {
            suggestions,
            incomplete: false, // Tell Monaco we have all suggestions
          };
        },
      });

    // Focus the editor
    editor.focus();

    // Adjust frame height
    Streamlit.setFrameHeight();
  };

  const handleEditorChange = (value: string | undefined) => {
    // Send the current value back to Streamlit
    Streamlit.setComponentValue(value || "");
  };

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: `${editorHeight + 10}px`, // +10px for resize handle
        position: "relative",
        zIndex: 1,
      }}
    >
      <div style={{ width: "100%", height: `${editorHeight}px`, position: "relative" }}>
        <Editor
          height={`${editorHeight}px`}
          defaultLanguage="sql"
          defaultValue={value}
          theme={theme}
          onMount={handleEditorDidMount}
          onChange={handleEditorChange}
          options={{
            minimap: { enabled: false },
            lineNumbers: "on",
            automaticLayout: true,
            fontSize: 14,
            tabSize: 2,
            wordWrap: "on",
            suggestLineHeight: 20, // Reasonable line height for suggestions
            suggestFontSize: 14,
            fixedOverflowWidgets: true, // Render suggestions in fixed overlay
            quickSuggestionsDelay: 0, // Show suggestions immediately
            suggest: {
              showKeywords: true,
              showSnippets: true,
              showClasses: true,
              showFunctions: true,
              showVariables: true,
              showFields: true,
              filterGraceful: false,
              snippetsPreventQuickSuggestions: false,
              showIcons: true,
              localityBonus: true,
              shareSuggestSelections: false,
            },
            quickSuggestions: {
              other: true,
              comments: false,
              strings: false,
            },
            suggestOnTriggerCharacters: true,
            acceptSuggestionOnEnter: "on",
            tabCompletion: "on",
            wordBasedSuggestions: "off",
          }}
        />
      </div>
      {/* Resize handle */}
      <div
        onMouseDown={handleMouseDown}
        style={{
          width: "100%",
          height: "10px",
          cursor: "ns-resize",
          backgroundColor: isResizing ? "#0066cc" : "#cccccc",
          borderTop: "1px solid #999",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          transition: isResizing ? "none" : "background-color 0.2s",
          userSelect: "none",
        }}
      >
        <div
          style={{
            width: "30px",
            height: "3px",
            backgroundColor: isResizing ? "#ffffff" : "#666666",
            borderRadius: "2px",
          }}
        />
      </div>
    </div>
  );
};

export default MonacoSqlEditor;
