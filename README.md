# Prevenção de ataques de SQL Injection - TCC 2025 - ASP.NET Core API

Demonstração completa de técnicas de prevenção de SQL Injection em uma API ASP.NET Core.

## 📋 Sobre o Projeto

Este projeto demonstra várias técnicas para prevenir ataques de SQL Injection em aplicações .NET, incluindo:

- ✅ **Consultas Parametrizadas** (ADO.NET)
- ✅ **Entity Framework Core** (parametrização automática)
- ✅ **Stored Procedures**
- ✅ **Validação Rigorosa de Inputs** (Whitelisting)
- ✅ **Análise Léxica para Detecção de SQL Injection**
- ✅ **Hash de Senhas com PBKDF2**
- ✅ **Validação de Formato (CPF, Email, etc.)**

## 🚀 Tecnologias

- ASP.NET Core 8.0
- Entity Framework Core 8.0
- SQL Server
- JWT Authentication
- Swagger/OpenAPI
- BCrypt.NET

## 📁 Estrutura do Projeto
SQLInjectionPreventionDemo/
├── Controllers/ # Controladores da API
├── Data/ # Contexto do BD e Entidades
├── Services/ # Serviços de aplicação
├── Repositories/ # Padrão Repository
├── DTOs/ # Data Transfer Objects
└── StoredProcedures/ # Procedures do SQL Server
