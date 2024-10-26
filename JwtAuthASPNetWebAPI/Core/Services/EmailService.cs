using JwtAuthASPNetWebAPI.Core.Interfaces;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using System.Net;
using System.Net.Mail;

namespace JwtAuthASPNetWebAPI.Core.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailConfiguration _emailConfig;
        public EmailService(EmailConfiguration emailConfig)
        {
            _emailConfig = emailConfig;
        }
        public Task Send(string email, string subject, string message)
        {
            var mail = _emailConfig.From;
            //lấy địa chỉ của người gửi từ cấu hình
            var password = _emailConfig.Password;
            //lấy password của ng gửi từ cấu hình
            var client = new SmtpClient(_emailConfig.SmtpServer, _emailConfig.Port)
            {
                EnableSsl = true,
                Credentials = new NetworkCredential(mail, password)
            };
            return client.SendMailAsync(new MailMessage(from: mail, to: email, subject, message));

        }
    }
}
