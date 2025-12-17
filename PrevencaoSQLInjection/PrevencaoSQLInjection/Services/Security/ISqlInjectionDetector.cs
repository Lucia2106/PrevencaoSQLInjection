namespace PrevencaoSQLInjection.Services.Security
{
    public interface ISqlInjectionDetector
    {
        bool ContainsSqlInjection(string input);
        string[] GetSqlKeywords();
        string[] GetSqlOperators();
    }
}
