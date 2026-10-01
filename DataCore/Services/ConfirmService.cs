using System;
using System.Linq;
using System.Security.Cryptography;
using DataCore.Interfaces;
using DataLayer.Context;
using DataLayer.Entity;

namespace DataCore.Services;

/// <summary>
/// سرویس ارسال و تأیید کد یکبار مصرف OTP
/// </summary>
public class ConfirmService : BaseRepository<Tbl_Confirm>, IConfirmService
{
    private readonly IMobileService _mobileService;

    // مدت اعتبار OTP
    private const int OtpExpireMinutes = 2;

    // حداکثر تعداد تلاش
    private const int MaxTryCount = 3;

    public ConfirmService(
        DatabaseContext db,
        IMobileService mobileService) : base(db)
    {
        _mobileService = mobileService;
    }

    /// <summary>
    /// تولید و ذخیره کد OTP جدید
    /// </summary>
    public void SendCode(string mobileNumber, string ipUser)
    {
        // ایجاد یا دریافت موبایل
        var mobile = _mobileService.Create(mobileNumber);

        if (mobile == null || mobile.Tc == Guid.Empty)
        {
            throw new InvalidOperationException(
                "اطلاعات شماره موبایل قابل ایجاد یا بازیابی نیست.");
        }

        // غیرفعال کردن کدهای قبلی همین شماره
        var oldConfirms = Set
            .Where(x =>
                x.Tc_Mobile == mobile.Tc &&
                !x.IsDelete &&
                x.IsActive &&
                !x.IsConfirmed)
            .ToList();

        foreach (var oldConfirm in oldConfirms)
        {
            oldConfirm.IsActive = false;
        }

        // تولید OTP تصادفی 4 رقمی
        var code = RandomNumberGenerator
            .GetInt32(1000, 10000)
            .ToString();

        var confirm = new Tbl_Confirm
        {
            Tc = Guid.NewGuid(),
            Tc_Mobile = mobile.Tc,
            Code = code,
            IpUser = string.IsNullOrWhiteSpace(ipUser) ? "-" : ipUser,
            SentDate = DateTime.Now,
            SentCount = 1,
            TryCount = 0,
            IsConfirmed = false,
            ConfirmDate = default,
            IsActive = true,
            IsDelete = false,
            RegisterData = DateTime.Now
        };

        var saved = Insert(confirm);

        if (!saved)
        {
            throw new InvalidOperationException(
                "کد تأیید در دیتابیس ذخیره نشد.");
        }
    }

    /// <summary>
    /// بررسی کد OTP وارد شده توسط کاربر
    /// </summary>
    public bool VerifyCode(
        string mobileNumber,
        string code,
        out string message)
    {
        message = string.Empty;

        if (string.IsNullOrWhiteSpace(mobileNumber))
        {
            message = "شماره موبایل وارد نشده است.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(code))
        {
            message = "کد تأیید وارد نشده است.";
            return false;
        }

        // پیدا کردن موبایل
        var mobile = Db.Tbl_Mobile
            .FirstOrDefault(x =>
                x.MobileNumber == mobileNumber &&
                !x.IsDelete &&
                x.IsActive);

        if (mobile == null)
        {
            message = "شماره موبایل یافت نشد.";
            return false;
        }

        // آخرین OTP فعال و تأیید نشده
        var confirm = Set
            .Where(x =>
                x.Tc_Mobile == mobile.Tc &&
                !x.IsDelete &&
                x.IsActive &&
                !x.IsConfirmed)
            .OrderByDescending(x => x.SentDate)
            .FirstOrDefault();

        if (confirm == null)
        {
            message = "کد تأیید فعالی برای این شماره وجود ندارد.";
            return false;
        }

        // بررسی انقضای کد
        if (confirm.SentDate.AddMinutes(OtpExpireMinutes) < DateTime.Now)
        {
            confirm.IsActive = false;
            Db.SaveChanges();

            message = "کد تأیید منقضی شده است. لطفاً مجدداً درخواست کد کنید.";
            return false;
        }

        // بررسی حداکثر تعداد تلاش
        if (confirm.TryCount >= MaxTryCount)
        {
            confirm.IsActive = false;
            Db.SaveChanges();
            message =
                "۳ بار کد تأیید اشتباه وارد شد. لطفاً مجدداً شماره موبایل خود را وارد کنید.";

            return false;
        }

        // افزایش تعداد تلاش در هر ورود
        confirm.TryCount++;

        // بررسی کد
        if (!string.Equals(
                confirm.Code?.Trim(),
                code.Trim(),
                StringComparison.Ordinal))
        {
            if (confirm.TryCount >= MaxTryCount)
            {
                confirm.IsActive = false;

                Db.SaveChanges();

                message =
                    "۳ بار کد تأیید اشتباه وارد شد. لطفاً مجدداً شماره موبایل خود را وارد کنید.";

                return false;
            }

            var remaining = MaxTryCount - confirm.TryCount;

            Db.SaveChanges();

            message =
                $"کد تأیید اشتباه است. {remaining} تلاش دیگر باقی مانده است.";

            return false;
        }

        // کد صحیح است
        confirm.IsConfirmed = true;
        confirm.ConfirmDate = DateTime.Now;
        confirm.IsActive = false;

        Db.SaveChanges();

        message = "کد تأیید با موفقیت تأیید شد.";

        return true;
    }

    public void SendCode(string mobileNumber)
    {
        throw new NotImplementedException();
    }

    public bool VerifyCode(string mobileNumber, string code)
    {
        throw new NotImplementedException();
    }
}