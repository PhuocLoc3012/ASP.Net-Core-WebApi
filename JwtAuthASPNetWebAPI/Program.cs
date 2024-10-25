﻿using JwtAuthASPNetWebAPI.Core.DbContext;
using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.Interfaces;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using JwtAuthASPNetWebAPI.Core.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

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


            //Add Db
            builder.Services.AddDbContext<ApplicationDBContext>(options => {
                var connectionString = builder.Configuration.GetConnectionString("local");
                options.UseSqlServer(connectionString);
            });


            //Add Identity
            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDBContext>()
                .AddDefaultTokenProviders();



            //* PHẦN NÀY CỦA BÊN EMAIL====================================================

            // Cấu hình thời gian sống cho token (ví dụ: token reset mật khẩu, xác nhận email)
            builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromHours(1); // Thời gian sống của token là 1 giờ
            });
            //* PHẦN NÀY CỦA BÊN EMAIL====================================================



            //Config Identity

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
                });




            //Inject app Dependecies (Dependency Injection)
            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddScoped<IEmailService, EmailService>();
            // Add services to the container.

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
}
