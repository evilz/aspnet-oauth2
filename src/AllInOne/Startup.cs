using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AllInOne
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options => options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AutomaticAuthenticate = true,
                LoginPath = new PathString("/login")
            });

            app.Map("/login", x =>
            {
                x.Run(async context =>
                {
                    var name = new Claim(ClaimTypes.Name, "toto");
                    var identity = new ClaimsIdentity(new[] {name }, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);

                    await context.Authentication.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                    context.Response.Redirect("/");
                });
            });

            app.Map("/logout", x =>
            {
                x.Run(async context =>
                {
                    await context.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/");
                });
            });


            app.Run(async (context) =>
            {
                var user = context.User;

                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync("<html><body>");

                if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                {
                    await context.Response.WriteAsync("<h1>Hello anonymous</h1>");
                    await context.Response.WriteAsync("<a href=\"/login\" > Login</a>");
                }
                else
                {
                    await context.Response.WriteAsync($"<h1>Hello {context.User.Identity.Name}</h1>");
                    foreach (var claim in context.User.Claims)
                    {
                        await context.Response.WriteAsync($"{claim.Type}: {claim.Value}<br>");
                    }
                    await context.Response.WriteAsync("<a href=\"/logout\">Logout</a><br>");
                }

                await context.Response.WriteAsync("</body></html>");
            });

        }
    }
}
