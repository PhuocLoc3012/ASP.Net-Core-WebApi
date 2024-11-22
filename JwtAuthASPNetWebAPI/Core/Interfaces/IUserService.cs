namespace JwtAuthASPNetWebAPI.Core.Interfaces
{
    public interface IUserService
    {
        Task DeleteUnconfirmedUserAsync();
    }
}
