CREATE OR ALTER PROCEDURE sp_GetUserByLogin
    @Login NVARCHAR(50)
AS
BEGIN
    SET NOCOUNT ON;
    
    SELECT 
        Id,
        Login,
        Email,
        PasswordHash,
        Salt,
        CreatedAt,
        LastLoginAt,
        FailedLoginAttempts,
        IsLocked,
        LockedUntil
    FROM Users
    WHERE Login = @Login;
END
GO