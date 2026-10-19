using System.Text;

using System.Threading.RateLimiting;

using Microsoft.AspNetCore.Authentication.JwtBearer;

using Microsoft.AspNetCore.Authorization;

using Microsoft.AspNetCore.RateLimiting;

using Microsoft.EntityFrameworkCore;

using Microsoft.IdentityModel.Tokens;

using Microsoft.OpenApi.Models;

using ProductsApi.Data;

using ProductsApi.Middleware;

using ProductsApi.Models;

using ProductsApi.Services;

using Serilog;

using Serilog.Events;



Log.Logger = new LoggerConfiguration()

    .MinimumLevel.Information()

    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)

    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)

    .Enrich.FromLogContext()

    .WriteTo.Console()

    .CreateBootstrapLogger();



try

{

    var builder = WebApplication.CreateBuilder(args);



    builder.Host.UseSerilog((context, services, configuration) => configuration

        .ReadFrom.Configuration(context.Configuration)

        .ReadFrom.Services(services)

        .Enrich.FromLogContext());



    builder.Services.AddControllers();

    builder.Services.AddEndpointsApiExplorer();

    builder.Services.AddSwaggerGen(options =>

    {

        options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme

        {

            Name = "Authorization",

            Type = SecuritySchemeType.Http,

            Scheme = "bearer",

            BearerFormat = "JWT",

            In = ParameterLocation.Header,

            Description = "Enter JWT token as: Bearer {token}"

        });

        options.AddSecurityRequirement(new OpenApiSecurityRequirement

        {

            {

                new OpenApiSecurityScheme

                {

                    Reference = new OpenApiReference

                    {

                        Type = ReferenceType.SecurityScheme,

                        Id = "Bearer"

                    }

                },

                Array.Empty<string>()

            }

        });

    });



    var jwtSection = builder.Configuration.GetSection("Jwt");

    var jwtKey = jwtSection["Key"] ?? throw new InvalidOperationException("Jwt:Key is not configured.");



    builder.Services

        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)

        .AddJwtBearer(options =>

        {

            options.TokenValidationParameters = new TokenValidationParameters

            {

                ValidateIssuer = true,

                ValidateAudience = true,

                ValidateLifetime = true,

                ValidateIssuerSigningKey = true,

                ValidIssuer = jwtSection["Issuer"],

                ValidAudience = jwtSection["Audience"],

                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),

                ClockSkew = TimeSpan.Zero

            };



            options.Events = new JwtBearerEvents

            {

                OnAuthenticationFailed = context =>

                {

                    Log.Warning(

                        context.Exception,

                        "JWT authentication failed for {Path}",

                        context.Request.Path);

                    return Task.CompletedTask;

                },

                OnChallenge = context =>

                {

                    Log.Warning(

                        "JWT challenge (401) for {Method} {Path}: {Error} {Description}",

                        context.Request.Method,

                        context.Request.Path,

                        context.Error,

                        context.ErrorDescription);

                    return Task.CompletedTask;

                }

            };

        });



    builder.Services.AddAuthorization(options =>

    {

        options.FallbackPolicy = new AuthorizationPolicyBuilder()

            .RequireAuthenticatedUser()

            .Build();

    });



    builder.Services.AddRateLimiter(options =>

    {

        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

        options.OnRejected = async (context, cancellationToken) =>

        {

            Log.Warning(

                "Rate limit exceeded for {Method} {Path} from {RemoteIp}",

                context.HttpContext.Request.Method,

                context.HttpContext.Request.Path,

                context.HttpContext.Connection.RemoteIpAddress);



            context.HttpContext.Response.ContentType = "application/json";

            await context.HttpContext.Response.WriteAsJsonAsync(

                new { message = "Too many requests. Please try again later." },

                cancellationToken);

        };



        options.AddFixedWindowLimiter("api", limiterOptions =>

        {

            limiterOptions.PermitLimit = builder.Configuration.GetValue("RateLimiting:Api:PermitLimit", 60);

            limiterOptions.Window = TimeSpan.FromMinutes(

                builder.Configuration.GetValue("RateLimiting:Api:WindowMinutes", 1));

            limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;

            limiterOptions.QueueLimit = 0;

        });



        options.AddFixedWindowLimiter("auth", limiterOptions =>

        {

            limiterOptions.PermitLimit = builder.Configuration.GetValue("RateLimiting:Auth:PermitLimit", 10);

            limiterOptions.Window = TimeSpan.FromMinutes(

                builder.Configuration.GetValue("RateLimiting:Auth:WindowMinutes", 1));

            limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;

            limiterOptions.QueueLimit = 0;

        });



        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>

        {

            var partitionKey = context.User.Identity?.IsAuthenticated == true

                ? context.User.Identity!.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "anonymous"

                : context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";



            return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions

            {

                AutoReplenishment = true,

                PermitLimit = builder.Configuration.GetValue("RateLimiting:Global:PermitLimit", 100),

                Window = TimeSpan.FromMinutes(builder.Configuration.GetValue("RateLimiting:Global:WindowMinutes", 1))

            });

        });

    });



    builder.Services.AddSingleton<JwtTokenService>();



    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));



    builder.Services.AddCors(options =>

    {

        options.AddPolicy("AllowAngular", policy =>

        {

            policy.WithOrigins("http://localhost:4200")

                  .AllowAnyHeader()

                  .AllowAnyMethod();

        });

    });



    var app = builder.Build();



    using (var scope = app.Services.CreateScope())

    {

        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Database.Migrate();

        if (!db.Products.Any())
        {
            db.Products.AddRange(

                new Product { Name = "Laptop", Description = "15-inch laptop", Price = 999.99m },

                new Product { Name = "Mouse", Description = "Wireless mouse", Price = 29.99m },

                new Product { Name = "Keyboard", Description = "Mechanical keyboard", Price = 79.99m }

            );

            db.SaveChanges();

        }

    }



    if (app.Environment.IsDevelopment())

    {

        app.UseSwagger();

        app.UseSwaggerUI();

    }



    app.UseMiddleware<ExceptionLoggingMiddleware>();

    app.UseSerilogRequestLogging(options =>

    {

        options.GetLevel = (httpContext, elapsed, ex) =>

            ex is not null ? LogEventLevel.Error

            : httpContext.Response.StatusCode >= 500 ? LogEventLevel.Error

            : httpContext.Response.StatusCode >= 400 ? LogEventLevel.Warning

            : LogEventLevel.Information;

    });



    app.UseHttpsRedirection();

    app.UseCors("AllowAngular");

    app.UseRateLimiter();

    app.UseAuthentication();

    app.UseAuthorization();



    app.MapControllers().RequireRateLimiting("api").RequireAuthorization();



    Log.Information("ProductsApi started. Log files: logs/errors-*.log, logs/app-*.log");

    app.Run();

}

catch (Exception ex)

{

    Log.Fatal(ex, "ProductsApi terminated unexpectedly");

    throw;

}

finally

{

    Log.CloseAndFlush();

}


