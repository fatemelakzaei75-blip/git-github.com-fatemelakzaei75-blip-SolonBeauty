using System.Text;
using System.Text.Json.Serialization;
using DataCore.Interfaces;
using DataCore.Services;
using DataLayer.Context;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using WebApiSolon.Middleware;
using WebApiSolon.Services;

var builder = WebApplication.CreateBuilder(args);

// در حالت توسعه می‌توان با UseInMemoryDatabase=true بدون SQL Server کار کرد
var useInMemory = builder.Configuration.GetValue<bool>("UseInMemoryDatabase");
builder.Services.AddDbContext<DatabaseContext>(options =>
{
    //if (useInMemory)
    //{
    //    options.UseInMemoryDatabase("SolonSalonDev");
    //}
    //else
    //{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    //}
});

// ثبت سرویس‌های اختصاصی احراز هویت و ذخیره‌سازی فایل
builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddScoped<FileStorageService>();
builder.Services.AddScoped<IFileStorageService, FileStorageService>();

// ثبت تمام سرویس‌های لایه DataCore
builder.Services.AddDataCoreServices();

// ---------- احراز هویت امنیتی JWT ----------
var jwtSection = builder.Configuration.GetSection("Jwt");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]!)),
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
    options.AddPolicy("PersonnelOnly", p => p.RequireRole("Personnel", "Admin"));
    options.AddPolicy("CustomerOnly", p => p.RequireRole("Customer", "Admin"));
});

// ---------- CORS برای کلاینت Blazor ----------
builder.Services.AddCors(options =>
{
    options.AddPolicy("BlazorClient", policy =>
    {
        policy.SetIsOriginAllowed(_ => true)
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Solon Salon API",
        Version = "v1",
        Description = "API مستند و استاندارد سالن زیبایی حدیث"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "توکن JWT را به صورت 'Bearer {token}' وارد کنید",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
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

var app = builder.Build();

// میدل‌ور مدیریت متمرکز و یکپارچه خطاها (Global Exception Handling)
app.UseMiddleware<GlobalExceptionMiddleware>();

// ساخت یا به‌روزرسانی خودکار دیتابیس
using (var scope = app.Services.CreateScope())
{
    try
    {
        var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        if (useInMemory)
        {
            db.Database.EnsureCreated();
            DevDataSeeder.Seed(db);
        }
        else
        {
            db.Database.Migrate();
        }
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "عملیات ارتقا یا ساخت دیتابیس با خطا مواجه شد.");
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// سرو فایل‌های بارگذاری شده از ریشه API (wwwroot/uploads)
Directory.CreateDirectory(Path.Combine(app.Environment.ContentRootPath, "wwwroot", FileStorageService.RootFolder));
app.UseStaticFiles();

app.UseCors("BlazorClient");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
