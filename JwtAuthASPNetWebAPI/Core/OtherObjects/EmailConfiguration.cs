using System.Runtime.Intrinsics.X86;

namespace JwtAuthASPNetWebAPI.Core.OtherObjects
{
    public class EmailConfiguration
    {

        //Địa chỉ email của người gửi
        public string From { get; set; }

        //Tên máy chủ SMTP để gửi email(ví dụ: smtp.gmail.com cho Gmail).
        public string SmtpServer { get; set; }

       // Cổng kết nối SMTP(ví dụ: 587 cho TLS/SSL).
        public int Port { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
