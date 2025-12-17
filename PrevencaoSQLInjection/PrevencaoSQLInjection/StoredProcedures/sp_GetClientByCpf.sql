CREATE OR ALTER PROCEDURE sp_GetClientByCpf
    @Cpf NVARCHAR(14)
AS
BEGIN
    SET NOCOUNT ON;
    
    SELECT 
        Id,
        Name,
        CPF,
        Email,
        Phone,
        CreatedAt,
        IsActive
    FROM Clients
    WHERE CPF = @Cpf;
END
GO