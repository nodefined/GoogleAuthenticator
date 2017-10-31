using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace GoogleAuthenticator
{
    public class TwoFactorAuthenticator
    {
        public static DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public TimeSpan DefaultClockDriftTolerance { get; set; }//容差时间
        public bool UseManagedSha1Algorithm { get; set; }
        public bool TryUnmanagedAlgorithmOnFailure { get; set; }

        public TwoFactorAuthenticator() : this(true, true) { }

        public TwoFactorAuthenticator(bool useManagedSha1, bool useUnmanagedOnFail)
        {
            DefaultClockDriftTolerance = TimeSpan.FromSeconds(60);//默认容差时间（60秒）
            UseManagedSha1Algorithm = useManagedSha1;
            TryUnmanagedAlgorithmOnFailure = useUnmanagedOnFail;
        }

        /// <summary>
        /// 无申请人ID生成Google Authenticator
        /// </summary>
        /// <param name="accountTitleNoSpaces">账户名</param>
        /// <param name="accountSecretKey">随机码</param>
        /// <param name="qrCodeWidth">二维码宽</param>
        /// <param name="qrCodeHeight">二维码高</param>
        /// <returns></returns>
        public SetupCode GenerateSetupCode(string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight)
        {
            return GenerateSetupCode(null, accountTitleNoSpaces, accountSecretKey, qrCodeWidth, qrCodeHeight);
        }

        /// <summary>
        /// 生成Google Authenticator
        /// </summary>
        /// <param name="issuer">申请人ID</param>
        /// <param name="accountTitleNoSpaces">账户名</param>
        /// <param name="accountSecretKey">随机码</param>
        /// <param name="qrCodeWidth">二维码宽</param>
        /// <param name="qrCodeHeight">二维码高</param>
        /// <returns></returns>
        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight)
        {
            return GenerateSetupCode(issuer, accountTitleNoSpaces, accountSecretKey, qrCodeWidth, qrCodeHeight, false);
        }

        /// <summary>
        /// 生成Google Authenticator
        /// </summary>
        /// <param name="issuer">申请人ID</param>
        /// <param name="accountTitleNoSpaces">账户名</param>
        /// <param name="accountSecretKey">随机码</param>
        /// <param name="qrCodeWidth">二维码宽</param>
        /// <param name="qrCodeHeight">二维码高</param>
        /// <param name="useHttps">使用https</param>
        /// <returns></returns>
        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight, bool useHttps)
        {
            if (accountTitleNoSpaces == null) { throw new NullReferenceException("Account Title is null"); }

            accountTitleNoSpaces = accountTitleNoSpaces.Replace(" ", "");

            SetupCode sC = new SetupCode();
            sC.Account = accountTitleNoSpaces;
            sC.AccountSecretKey = accountSecretKey;

            string encodedSecretKey = EncodeAccountSecretKey(accountSecretKey);
            sC.ManualEntryKey = encodedSecretKey;

            string provisionUrl = null;

            if (string.IsNullOrEmpty(issuer))
            {
                provisionUrl = String.Format("otpauth://totp/{0}?secret={1}", accountTitleNoSpaces, encodedSecretKey); 
            }
            else
            {
                provisionUrl = String.Format("otpauth://totp/{0}?secret={1}&issuer={2}", accountTitleNoSpaces, encodedSecretKey, UrlEncode(issuer));
            }

            sC.QrCodeSetupImageUrl = provisionUrl;

            return sC;
        }
        /// <summary>
        /// Url编码
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private string UrlEncode(string value)
        {
            StringBuilder result = new StringBuilder();
            string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            foreach (char symbol in value)
            {
                if (validChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + String.Format("{0:X2}", (int)symbol));
                }
            }

            return result.ToString().Replace(" ", "%20");
        }

        private string EncodeAccountSecretKey(string accountSecretKey)
        {
            return Base32Encode(Encoding.UTF8.GetBytes(accountSecretKey));
        }
        /// <summary>
        /// Base32加密
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private string Base32Encode(byte[] data)
        {
            int inByteSize = 8;
            int outByteSize = 5;
            char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

            int i = 0, index = 0, digit = 0;
            int current_byte, next_byte;
            StringBuilder result = new StringBuilder((data.Length + 7) * inByteSize / outByteSize);

            while (i < data.Length)
            {
                current_byte = (data[i] >= 0) ? data[i] : (data[i] + 256); // Unsign

                //是否越界？
                if (index > (inByteSize - outByteSize))
                {
                    if ((i + 1) < data.Length)
                        next_byte = (data[i + 1] >= 0) ? data[i + 1] : (data[i + 1] + 256);
                    else
                        next_byte = 0;

                    digit = current_byte & (0xFF >> index);
                    index = (index + outByteSize) % inByteSize;
                    digit <<= index;
                    digit |= next_byte >> (inByteSize - index);
                    i++;
                }
                else
                {
                    digit = (current_byte >> (inByteSize - (index + outByteSize))) & 0x1F;
                    index = (index + outByteSize) % inByteSize;
                    if (index == 0)
                        i++;
                }
                result.Append(alphabet[digit]);
            }

            return result.ToString();
        }

        public string GeneratePINAtInterval(string accountSecretKey, long counter, int digits = 6)
        {
            return GenerateHashedCode(accountSecretKey, counter, digits);
        }

        internal string GenerateHashedCode(string secret, long iterationNumber, int digits = 6)
        {
            byte[] key = Encoding.UTF8.GetBytes(secret);
            return GenerateHashedCode(key, iterationNumber, digits);
        }

        internal string GenerateHashedCode(byte[] key, long iterationNumber, int digits = 6)
        {
            byte[] counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counter);
            }

            HMACSHA1 hmac = getHMACSha1Algorithm(key);

            byte[] hash = hmac.ComputeHash(counter);

            int offset = hash[hash.Length - 1] & 0xf;

            //将4个字节转换成整数，忽略符号
            int binary =
                ((hash[offset] & 0x7f) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | (hash[offset + 3]);

            int password = binary % (int)Math.Pow(10, digits);
            return password.ToString(new string('0', digits));
        }

        private long GetCurrentCounter()
        {
            return GetCurrentCounter(DateTime.UtcNow, _epoch, 30);
        }

        private long GetCurrentCounter(DateTime now, DateTime epoch, int timeStep)
        {
            return (long)(now - epoch).TotalSeconds / timeStep;
        }

        /// <summary>
        /// 创建一个HMACSHA1
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>        
        private HMACSHA1 getHMACSha1Algorithm(byte[] key)
        {
            HMACSHA1 hmac;

            try
            {
                hmac = new HMACSHA1(key, UseManagedSha1Algorithm);
            }
            catch (InvalidOperationException ioe)
            {
                if (UseManagedSha1Algorithm && TryUnmanagedAlgorithmOnFailure)
                {
                    try
                    {
                        hmac = new HMACSHA1(key, false);
                    }
                    catch (InvalidOperationException ioe2)
                    {
                        throw ioe2;
                    }
                }
                else
                {
                    throw ioe;
                }
            }

            return hmac;
        }
        /// <summary>
        /// 验证动态码是否正确
        /// </summary>
        /// <param name="accountSecretKey">随机码</param>
        /// <param name="twoFactorCodeFromClient">要验证的动态码</param>
        /// <returns></returns>
        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient)
        {
            return ValidateTwoFactorPIN(accountSecretKey, twoFactorCodeFromClient, DefaultClockDriftTolerance);
        }

        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient, TimeSpan timeTolerance)
        {
            var codes = GetCurrentPINs(accountSecretKey, timeTolerance);
            return codes.Any(c => c == twoFactorCodeFromClient);
        }

        public string GetCurrentPIN(string accountSecretKey)
        {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter());
        }

        public string GetCurrentPIN(string accountSecretKey, DateTime now)
        {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter(now, _epoch, 30));
        }

        public string[] GetCurrentPINs(string accountSecretKey)
        {
            return GetCurrentPINs(accountSecretKey, DefaultClockDriftTolerance);
        }

        public string[] GetCurrentPINs(string accountSecretKey, TimeSpan timeTolerance)
        {
            List<string> codes = new List<string>();
            long iterationCounter = GetCurrentCounter();
            int iterationOffset = 0;

            if (timeTolerance.TotalSeconds > 30)
            {
                iterationOffset = Convert.ToInt32(timeTolerance.TotalSeconds / 30.00);
            }

            long iterationStart = iterationCounter - iterationOffset;
            long iterationEnd = iterationCounter + iterationOffset;

            for (long counter = iterationStart; counter <= iterationEnd; counter++)
            {
                codes.Add(GeneratePINAtInterval(accountSecretKey, counter));
            }
            return codes.ToArray();
        }
    }
}
