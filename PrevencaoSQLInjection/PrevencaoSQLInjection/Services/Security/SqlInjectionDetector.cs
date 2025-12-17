namespace PrevencaoSQLInjection.Services.Security
{
    public class SqlInjectionDetector : ISqlInjectionDetector
    {
        private readonly string[] _sqlKeywords =
        {
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "EXEC", "EXECUTE", "UNION", "JOIN", "FROM", "WHERE", "HAVING",
            "GROUP BY", "ORDER BY", "INTO", "VALUES", "SET", "TABLE"
        };

        private readonly string[] _sqlOperators =
        {
            "'", "\"", ";", "--", "/*", "*/", "@@", "CHAR", "ASCII", "WAITFOR",
            "DELAY", "SHUTDOWN", "XP_", "SP_", "DBCC"
        };

        public bool ContainsSqlInjection(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            var upperInput = input.ToUpperInvariant();

            // Check for SQL keywords
            foreach (var keyword in _sqlKeywords)
            {
                if (upperInput.Contains(keyword) &&
                    (upperInput.Contains("'") || upperInput.Contains("--") || upperInput.Contains(";") ||
                     upperInput.Contains("/*") || upperInput.Contains("*/")))
                {
                    return true;
                }
            }

            // Check for suspicious patterns
            foreach (var op in _sqlOperators)
            {
                if (upperInput.Contains(op))
                {
                    return true;
                }
            }

            // Check for always true conditions
            if (upperInput.Contains("OR '1'='1") || upperInput.Contains("OR 1=1") ||
                upperInput.Contains("OR 'A'='A") || upperInput.Contains("OR 'X'='X"))
            {
                return true;
            }

            return false;
        }

        public string[] GetSqlKeywords() => _sqlKeywords;

        public string[] GetSqlOperators() => _sqlOperators;
    }
}
