using System;

namespace DataCore.Interfaces
{
    public interface IConfirmService
    {
        void SendCode(string mobileNumber, string ipUser);

        bool VerifyCode(
            string mobileNumber,
            string code,
            out string message);
    }
}