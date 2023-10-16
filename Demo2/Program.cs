using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Demo2.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Demo2
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddAuthentication(
                options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                    
                }).AddJwtBearer(o =>
            {
            o.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.ASCII.GetBytes(builder.Configuration["Jwt:SecretKey"])),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true
            };
        });
            builder.Services.AddAuthorization();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            app.UseAuthentication();
            app.UseAuthorization();

            //    var summaries = new[]
            //    {
            //    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
            //};

            app.MapGet("/security/getmessage", () => "Hello World!").RequireAuthorization();
            app.MapPost("security/token", [AllowAnonymous] (User user) =>
                {
                    if (user.Username == "alex" && user.Password == "123")
                    {
                        
                        var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:SecretKey"]);
                        var tokenDescriptor = new SecurityTokenDescriptor()
                        {
                            Subject = new ClaimsIdentity(new List<Claim>
                            {
                                new Claim("Id", Guid.NewGuid().ToString()),
                                new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                                new Claim(JwtRegisteredClaimNames.Email, user.Username),
                                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                            }),
                            Expires = DateTime.Now.AddDays(30),
                            SigningCredentials =
                                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
                        };
                        var tokenHandler = new JwtSecurityTokenHandler();
                        var token = tokenHandler.CreateToken(tokenDescriptor);
                        return Results.Ok(tokenHandler.WriteToken(token));
                    }

                    return Results.Unauthorized();
                }

            );
            app.Run();
        }
    }
}