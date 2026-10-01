using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using DataCore.Interfaces;
using DataCore.Models.Common;
using DataCore.Models.ViewModels;
using DataCore.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using WebApiSolon.Models;
using WebApiSolon.Services;

namespace WebApiSolon.Controllers;

/// <summary>
/// کنترلر احراز هویت کاربران، ورود با OTP و رمز عبور و صدور JWT
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : BaseApiController
{
    private readonly IConfirmService _confirmService;
    private readonly IMobileService _mobileService;
    private readonly ICustomerService _customerService;
    private readonly UserRoleService _userRoleService;
    private readonly JwtTokenService _jwtTokenService;
    private readonly ILogger<AuthController> _logger;

    private static readonly Dictionary<string, (string Name, string Role)> DemoUsers = new()
    {
        ["09120000001"] = ("مدیر سالن حدیث", "Admin"),
        ["09120000002"] = ("سارا محمدی (پرسنل)", "Personnel"),
        ["09120000003"] = ("نگار رضایی (مشتری)", "Customer"),
    };

    public AuthController(
        IConfirmService confirmService,
        IMobileService mobileService,
        ICustomerService customerService,
        UserRoleService userRoleService,
        JwtTokenService jwtTokenService,
        ILogger<AuthController> logger)
    {
        _confirmService = confirmService;
        _mobileService = mobileService;
        _customerService = customerService;
        _userRoleService = userRoleService;
        _jwtTokenService = jwtTokenService;
        _logger = logger;
    }

    /// <summary>
    /// ارسال کد تأیید ورود به شماره همراه
    /// </summary>
    [HttpPost("send-code")]
    public ActionResult SendCode([FromBody] SendCodeRequest request)
    {
        request.MobileNumber = DigitHelper.Normalize(request.MobileNumber);

        if (!IsValidMobile(request.MobileNumber))
        {
            return BadRequest(new
            {
                Success = false,
                Message = "شماره موبایل معتبر نمی‌باشد."
            });
        }

        try
        {
            var ipUser =
                HttpContext.Connection.RemoteIpAddress?.ToString()
                ?? "-";

            _confirmService.SendCode(
                request.MobileNumber,
                ipUser);

            Response.Headers.Append(
                "Link",
                "</api/auth/login>; rel=\"login-otp\"");

            return Ok(new
            {
                Success = true,
                Message = "کد تأیید با موفقیت ایجاد شد."
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "خطا در ایجاد کد تأیید برای شماره {MobileNumber}",
                request.MobileNumber);

            return StatusCode(500, new
            {
                Success = false,
                Message = "در ایجاد کد تأیید خطایی رخ داد."
            });
        }
    }

    /// <summary>
    /// ورود با شماره موبایل و کد یکبار مصرف OTP
    /// </summary>
    [HttpPost("login")]
    public ActionResult<LoginResponse> Login(
        [FromBody] LoginRequest request)
    {
        request.MobileNumber =
            DigitHelper.Normalize(request.MobileNumber);

        request.Code =
            DigitHelper.Normalize(request.Code);

        if (!IsValidMobile(request.MobileNumber) ||
            string.IsNullOrWhiteSpace(request.Code))
        {
            return BadRequest(new
            {
                Success = false,
                Message = "شماره همراه یا کد تأیید نامعتبر است."
            });
        }

        // بررسی واقعی کد OTP از دیتابیس
        var verified = _confirmService.VerifyCode(
            request.MobileNumber,
            request.Code,
            out var verifyMessage);


        if (!verified)
        {
            return Unauthorized(new
            {
                Success = false,
                Message = verifyMessage
            });
        }

        try
        {
            // دریافت یا ایجاد رکورد موبایل
            var mobile =
                _mobileService.Create(request.MobileNumber);

            if (mobile == null ||
                mobile.Tc == Guid.Empty)
            {
                return Unauthorized(new
                {
                    Success = false,
                    Message = "اطلاعات شماره موبایل قابل بازیابی نیست."
                });
            }

            var tc = mobile.Tc;

            var roles = new List<string>();

            var displayName =
                $"کاربر {request.MobileNumber[^4..]}";

            // بررسی پرسنل
            if (Guid.TryParse(
                    mobile.TcPersonal,
                    out var personalTc) &&
                personalTc != Guid.Empty)
            {
                tc = personalTc;

                roles =
                    _userRoleService
                        .GetRoleNamesByPersonalTc(personalTc);

                if (roles == null)
                {
                    roles = new List<string>();
                }

                displayName = "پرسنل سالن";
            }
            // بررسی مشتری
            else if (_customerService.IsCustomerExists(mobile.Tc))
            {
                var customer =
                    _customerService.GetCustomerByToken(mobile.Tc);

                if (customer != null)
                {
                    displayName = customer.FullName;
                }

                roles.Add("Customer");
            }
            // شماره تأیید شده ولی هنوز پروفایل مشتری ندارد
            else
            {
                roles.Add("Customer");
            }

            var (token, expires) =
                _jwtTokenService.CreateToken(
                    tc,
                    displayName,
                    request.MobileNumber,
                    roles);

            Response.Headers.Append(
                "Link",
                "</api/auth/me>; rel=\"me\"");

            return Ok(new LoginResponse
            {
                Token = token,
                ExpiresAt = expires,
                DisplayName = displayName,
                MobileNumber = request.MobileNumber,
                Tc = tc,
                Roles = roles
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "خطا در ورود کاربر با شماره {MobileNumber}",
                request.MobileNumber);

            return StatusCode(500, new
            {
                Success = false,
                Message = ex.Message,
                Detail = ex.InnerException?.Message
            });
        }
    }

    /// <summary>
    /// بازیابی کلمه عبور با استفاده از کد پیامکی
    /// </summary>
    [HttpPost("reset-password")]
    public ActionResult ResetPassword(
        [FromBody] ResetPasswordRequest request)
    {
        request.MobileNumber =
            DigitHelper.Normalize(request.MobileNumber);

        request.Code =
            DigitHelper.Normalize(request.Code);

        if (!IsValidMobile(request.MobileNumber) ||
            string.IsNullOrWhiteSpace(request.Code) ||
            string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new
            {
                Success = false,
                Message = "اطلاعات ارسالی کامل نمی‌باشد."
            });
        }

        var verified =
            _confirmService.VerifyCode(
                request.MobileNumber,
                request.Code,
                out var verifyMessage);

        if (!verified)
        {
            return Unauthorized(new
            {
                Success = false,
                Message = verifyMessage
            });
        }

        // فعلاً فقط تأیید کد انجام می‌شود.
        // ذخیره واقعی رمز عبور در مرحله بعد پیاده‌سازی می‌شود.

        return Ok(new
        {
            Success = true,
            Message = "کد تأیید با موفقیت تأیید شد."
        });
    }

    /// <summary>
    /// ورود با شماره موبایل و رمز عبور ثابت
    /// </summary>
    [HttpPost("login-password")]
    public ActionResult<LoginResponse> LoginWithPassword(
        [FromBody] LoginPasswordRequest request)
    {
        request.MobileNumber =
            DigitHelper.Normalize(request.MobileNumber);

        if (!IsValidMobile(request.MobileNumber) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new
            {
                Success = false,
                Message = "شماره همراه یا کلمه عبور نامعتبر است."
            });
        }

        if (request.Password != "123456" &&
            request.Password != "Admin@123456")
        {
            return Unauthorized(new
            {
                Success = false,
                Message =
                    "کلمه عبور وارد شده نادرست است."
            });
        }

        if (!DemoUsers.TryGetValue(
                request.MobileNumber,
                out var demo))
        {
            var customerTc = Guid.NewGuid();

            var roles =
                new List<string> { "Customer" };

            var (token, expires) =
                _jwtTokenService.CreateToken(
                    customerTc,
                    $"کاربر {request.MobileNumber[^4..]}",
                    request.MobileNumber,
                    roles);

            return Ok(new LoginResponse
            {
                Token = token,
                ExpiresAt = expires,
                DisplayName =
                    $"کاربر {request.MobileNumber[^4..]}",
                MobileNumber =
                    request.MobileNumber,
                Tc = customerTc,
                Roles = roles
            });
        }

        var (demoToken, demoExpires) =
            _jwtTokenService.CreateToken(
                Guid.NewGuid(),
                demo.Name,
                request.MobileNumber,
                new List<string> { demo.Role });

        return Ok(new LoginResponse
        {
            Token = demoToken,
            ExpiresAt = demoExpires,
            DisplayName = demo.Name,
            MobileNumber = request.MobileNumber,
            Tc = Guid.NewGuid(),
            Roles = new List<string> { demo.Role }
        });
    }

    /// <summary>
    /// دریافت پروفایل و نقش‌های کاربر جاری از JWT
    /// </summary>
    [Authorize]
    [HttpGet("me")]
    public ActionResult<LoginResponse> Me()
    {
        return Ok(new LoginResponse
        {
            DisplayName =
                User.FindFirstValue(ClaimTypes.Name) ?? "",

            MobileNumber =
                User.FindFirstValue(ClaimTypes.MobilePhone) ?? "",

            Tc =
                Guid.TryParse(
                    User.FindFirstValue(
                        ClaimTypes.NameIdentifier),
                    out var g)
                    ? g
                    : Guid.Empty,

            Roles =
                User.FindAll(ClaimTypes.Role)
                    .Select(c => c.Value)
                    .ToList()
        });
    }

    private static bool IsValidMobile(string mobile)
    {
        return Regex.IsMatch(
            mobile,
            @"^09\d{9}$");
    }
}