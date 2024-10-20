namespace JwtAuthASPNetWebAPI.Core.Interfaces
{
    public interface IEmailService
    {
        Task Send(string email, string subject, string message);
        //email ng nhận
        //tiêu đề email
        //nội dung email

    }
}
