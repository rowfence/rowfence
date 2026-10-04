; the SQL inside { } is SQL
((sql_text) @injection.content
  (#set! injection.language "sql")
  (#set! injection.include-children))
