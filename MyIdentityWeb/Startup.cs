using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Http;
using MyIdentityWeb.Models;
using MyIdentityWeb.Services;
using AspNetCore.Identity.MongoDB;
using MongoDB.Driver;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MyIdentityWeb
{
    public class Startup
    {
        private readonly IHostingEnvironment _env;

        public Startup(IConfiguration configuration, IHostingEnvironment env)
        {
            Configuration = configuration;
            _env = env;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<MongoDbSettings>(Configuration.GetSection("MongoDb"));
            services.AddSingleton<IUserStore<MongoIdentityUser>>(provider =>
            {
                var options = provider.GetService<IOptions<MongoDbSettings>>();
                var client = new MongoClient(options.Value.ConnectionString);
                var database = client.GetDatabase(options.Value.DatabaseName);
                return new MongoUserStore<MongoIdentityUser>(database);
            });

            // Configure Identity
            services.Configure<IdentityOptions>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = false;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 10;

                //// Cookie settings
                //options.Cookies.ApplicationCookie.ExpireTimeSpan = TimeSpan.FromDays(150);
                //options.Cookies.ApplicationCookie.LoginPath = "/Account/LogIn";
                //options.Cookies.ApplicationCookie.LogoutPath = "/Account/LogOut";

                // User settings
                options.User.RequireUniqueEmail = true;
            });

            
            services.AddAuthentication(options =>
            {                
                //options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {                
                options.Cookie.Name = ".AuthCookie";                
                options.Cookie.Path = Path.Combine(_env.WebRootPath, "identity-artifacts");
                //options.Cookie.HttpOnly = true;
                //options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                //var dataProtectionPath = Path.Combine(_env.WebRootPath, "identity-artifacts");
                //options.DataProtectionProvider = DataProtectionProvider.Create(dataProtectionPath);
            });

            //services.ConfigureApplicationCookie(options =>
            //{
            //    var dataProtectionPath = Path.Combine(_env.WebRootPath, "identity-artifacts");                
            //    options.DataProtectionProvider = DataProtectionProvider.Create(dataProtectionPath);
            //    options.LoginPath = "/Account/LogIn";
            //    });

            //services.Configure<IdentityOptions>(options =>
            //{
            //    var dataProtectionPath = Path.Combine(_env.WebRootPath, "identity-artifacts");
            //    options.Cookies.ApplicationCookie.AuthenticationScheme = "ApplicationCookie";
            //    options.Cookies.ApplicationCookie.DataProtectionProvider = DataProtectionProvider.Create(dataProtectionPath);
            //    options.Lockout.AllowedForNewUsers = true;
            //});


            //// Services used by identity
            //services.AddAuthentication(options =>
            //{
            //    // This is the Default value for ExternalCookieAuthenticationScheme
            //    options.DefaultSignInScheme = new IdentityCookieOptions().ExternalCookieAuthenticationScheme;
            //});

            // Hosting doesn't add IHttpContextAccessor by default
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddOptions();
            services.AddDataProtection();
            
            //services.AddSingleton<IdentityMarkerService>();
            services.AddSingleton<IUserValidator<MongoIdentityUser>, UserValidator<MongoIdentityUser>>();
            services.AddSingleton<IPasswordValidator<MongoIdentityUser>, PasswordValidator<MongoIdentityUser>>();
            services.AddSingleton<IPasswordHasher<MongoIdentityUser>, PasswordHasher<MongoIdentityUser>>();
            services.AddSingleton<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            services.AddSingleton<IdentityErrorDescriber>();
            services.AddSingleton<ISecurityStampValidator, SecurityStampValidator<MongoIdentityUser>>();
            services.AddSingleton<IUserClaimsPrincipalFactory<MongoIdentityUser>, UserClaimsPrincipalFactory<MongoIdentityUser>>();
            services.AddSingleton<UserManager<MongoIdentityUser>, UserManager<MongoIdentityUser>>();
            services.AddScoped<SignInManager<MongoIdentityUser>, SignInManager<MongoIdentityUser>>();
            AddDefaultTokenProviders(services);

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();
                        
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }


        #region AspNetCore.Identity.MongoDB Specific
        private void AddDefaultTokenProviders(IServiceCollection services)
        {
            var dataProtectionProviderType = typeof(DataProtectorTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            var phoneNumberProviderType = typeof(PhoneNumberTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            var emailTokenProviderType = typeof(EmailTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            AddTokenProvider(services, TokenOptions.DefaultProvider, dataProtectionProviderType);
            AddTokenProvider(services, TokenOptions.DefaultEmailProvider, emailTokenProviderType);
            AddTokenProvider(services, TokenOptions.DefaultPhoneProvider, phoneNumberProviderType);
        }

        private void AddTokenProvider(IServiceCollection services, string providerName, Type provider)
        {
            services.Configure<IdentityOptions>(options =>
            {
                options.Tokens.ProviderMap[providerName] = new TokenProviderDescriptor(provider);
            });

            services.AddSingleton(provider);
        }

        public class UserClaimsPrincipalFactory<TUser> : IUserClaimsPrincipalFactory<TUser>
            where TUser : class
        {
            public UserClaimsPrincipalFactory(
                UserManager<TUser> userManager,
                IOptions<IdentityOptions> optionsAccessor)
            {
                if (userManager == null)
                {
                    throw new ArgumentNullException(nameof(userManager));
                }
                if (optionsAccessor == null || optionsAccessor.Value == null)
                {
                    throw new ArgumentNullException(nameof(optionsAccessor));
                }

                UserManager = userManager;
                Options = optionsAccessor.Value;
            }

            public UserManager<TUser> UserManager { get; private set; }

            public IdentityOptions Options { get; private set; }

            public virtual async Task<ClaimsPrincipal> CreateAsync(TUser user)
            {
                if (user == null)
                {
                    throw new ArgumentNullException(nameof(user));
                }

                var userId = await UserManager.GetUserIdAsync(user);
                var userName = await UserManager.GetUserNameAsync(user);

                //var id = new ClaimsIdentity(Options.Cookies.ApplicationCookieAuthenticationScheme,
                //    Options.ClaimsIdentity.UserNameClaimType,
                //    Options.ClaimsIdentity.RoleClaimType);
                var id = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme,
                    Options.ClaimsIdentity.UserNameClaimType,
                    Options.ClaimsIdentity.RoleClaimType);
                id.AddClaim(new Claim(Options.ClaimsIdentity.UserIdClaimType, userId));
                id.AddClaim(new Claim(Options.ClaimsIdentity.UserNameClaimType, userName));
                if (UserManager.SupportsUserSecurityStamp)
                {
                    id.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType,
                        await UserManager.GetSecurityStampAsync(user)));
                }
                if (UserManager.SupportsUserRole)
                {
                    var roles = await UserManager.GetRolesAsync(user);
                    foreach (var roleName in roles)
                    {
                        id.AddClaim(new Claim(Options.ClaimsIdentity.RoleClaimType, roleName));
                    }
                }
                if (UserManager.SupportsUserClaim)
                {
                    id.AddClaims(await UserManager.GetClaimsAsync(user));
                }

                return new ClaimsPrincipal(id);
            }
        }
        #endregion

    }
}
