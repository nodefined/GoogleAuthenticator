using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GoogleAuthenticator
{
    public class SetupCode
    {
        public string Account { get; set; }//账号
        public string AccountSecretKey { get; set; }//随机码
        public string ManualEntryKey { get; set; }//密钥
        public string QrCodeSetupImageUrl { get; set; }//二维码路径
    }
}
