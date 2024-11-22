using JwtAuthASPNetWebAPI.Core.DbContext;
using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.Interfaces;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using JwtAuthASPNetWebAPI.Core.Services;
using JwtAuthASPNetWebAPI.Jobs;
using JwtAuthASPNetWebAPI.Utils;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Quartz;
using System.Text;

using Quartz.Spi;

namespace JwtAuthASPNetWebAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();


            //Add DbContext
            builder.Services.AddDbContext<ApplicationDBContext>(options => {
                var connectionString = builder.Configuration.GetConnectionString("local");
                options.UseSqlServer(connectionString);
            });


            //Add Identity
            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDBContext>()
                .AddDefaultTokenProviders();



            //* PHẦN NÀY CỦA BÊN EMAIL====================================================
            // Token lifespan configuration for email tokens
            // Cấu hình thời gian sống cho token (ví dụ: token reset mật khẩu, xác nhận email)
            builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromHours(1); // Thời gian sống của token là 1 giờ
            });
            //* PHẦN NÀY CỦA BÊN EMAIL====================================================



            // // Identity configuration

            builder.Services.Configure<IdentityOptions>(options => {
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.SignIn.RequireConfirmedEmail = false;

            });


            //Add Authencation and JwtBearer

            builder.Services
                .AddAuthentication(options => {
                    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidIssuer = builder.Configuration["Jwt:ValidIssuer"],
                        ValidAudience = builder.Configuration["Jwt:ValidAudience"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"]))
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = ctx =>
                        {
                            ctx.Request.Cookies.TryGetValue("accessToken", out var accessToken);
                            if (!string.IsNullOrEmpty(accessToken))
                                ctx.Token = accessToken;
                            return Task.CompletedTask;
                        }
                    };
                })
                //Auth Google
                .AddGoogle(options => 
                {
                    options.ClientId = builder.Configuration["Google:ClientId"];
                    options.ClientSecret = builder.Configuration["Google:ClientSecret"];
                    options.CallbackPath = "/signin-google";
                });




            //Inject app Dependecies (Dependency Injection)
            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddScoped<IEmailService, EmailService>();
            builder.Services.AddScoped<ITokenService, TokenService>();  
            builder.Services.AddScoped<IUserService, UserService>();

            // Add services to the container.
            builder.Services.AddScoped<TokenProvider>();
            builder.Services.AddScoped<DeleteUnconfirmedUsersJob> ();
            // Email configuration
            var emailConfig = builder.Configuration
                .GetSection("EmailConfiguration")
                .Get<EmailConfiguration>();
            builder.Services.AddSingleton(emailConfig);

           



            //Add CORS
            builder.Services.AddCors(p => p.AddPolicy("MyCors", build =>
            {
                //build.WithOrigins("https://test.infor", "https://localhost:3000");
                build.WithOrigins("*").AllowAnyMethod().AllowAnyHeader();
            }));


            // Thêm Quartz vào container DI
            builder.Services.AddQuartz(q =>
            {
                // Sử dụng Microsoft Dependency Injection để tạo Job
                q.UseMicrosoftDependencyInjectionJobFactory();

                // Định nghĩa Job và Trigger
                q.ScheduleJob<DeleteUnconfirmedUsersJob>(trigger => trigger
                    .WithIdentity("DeleteUnconfirmedUsersTrigger")
                    .StartNow()
                    .WithSimpleSchedule(x => x.WithIntervalInHours(24).RepeatForever())
                );
            });




            ////Đây là authentication Google

            //builder.Services.AddAuthentication(options =>
            //{
            //    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;

            //}).AddCookie()
            //.AddGoogle(options =>
            //{
            //    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.ClientId = builder.Configuration["Google:ClientId"];
            //    options.ClientSecret = builder.Configuration["Google:ClientSecret"];
            //})
            //    ;



            //Add jobs





            //pipeline
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseCors("MyCors");// CORS
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();



        }


    }

    // Hosted Service to manage Quartz lifecycle
    public class QuartzHostedService : IHostedService
    {
        private readonly ISchedulerFactory _schedulerFactory;
        private readonly IScheduler _scheduler;

        public QuartzHostedService(ISchedulerFactory schedulerFactory)
        {
            _schedulerFactory = schedulerFactory;
            _scheduler = _schedulerFactory.GetScheduler().Result;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            // Start the Quartz scheduler
            await _scheduler.Start(cancellationToken);
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            // Shutdown the Quartz scheduler
            await _scheduler.Shutdown(cancellationToken);
        }
    }
}
