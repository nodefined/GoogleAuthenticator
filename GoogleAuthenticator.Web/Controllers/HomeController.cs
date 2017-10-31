using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using GoogleAuthenticator.Web.Helper;
using GoogleAuthenticator.Web.Models;

namespace GoogleAuthenticator.Web.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Reg()
        {

            return View();
        }
        /// <summary>
        /// 随机密钥
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        public ActionResult getManualEntryKey(string account)
        {
            bool statu = false;
            //产生一个随机码
            string accountSecretKey = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            var setupCode = tfa.GenerateSetupCode(account, accountSecretKey, 300, 300);
            var path = @"/App_Data/usersdata.xml";
            XmlSerializerHelper xmlHelper = new XmlSerializerHelper(Server.MapPath(path));
            var users = xmlHelper.Deserialize<List<UserModel>>();
            var user= users.Where(o => o.UserName == account).FirstOrDefault();
            if (user==null)
            {
                statu = true;
            }
            return Json(new { msg = setupCode, statu = statu }, JsonRequestBehavior.AllowGet);
        }

        /// <summary>
        /// 注册
        /// </summary>
        /// <param name="accountSecretKey"></param>
        /// <param name="inputCode"></param>
        /// <returns></returns>
        public ActionResult register(string accountSecretKey, string inputCode, string account, string passWord)
        {
            string result = "注册失败";
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();

            var statu = tfa.ValidateTwoFactorPIN(accountSecretKey, inputCode);
            //验证通过，写入xml文档
            if (statu)
            {
                List<UserModel> userModels = new List<UserModel>();
                UserModel user = new UserModel()
                {
                    UserName = account,
                    PassWord = passWord,
                    AccountSecretKey = accountSecretKey
                };
                userModels.Add(user);
                var path = @"/App_Data/usersdata.xml";
                XmlSerializerHelper xmlHelper = new XmlSerializerHelper(Server.MapPath(path));
                //先读取
                userModels.AddRange(xmlHelper.Deserialize<List<UserModel>>());
                xmlHelper.Serialize<List<UserModel>>(userModels);
                result = "注册成功";
            }
            return Json(new { msg = result, statu = statu }, JsonRequestBehavior.AllowGet);
        }

        public ActionResult login(string userName, string passWord, string code)
        {
            string result = string.Empty;
            bool statu = false;
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            //从xml文件里读取用户信息
            List<UserModel> userModels = new List<UserModel>();
            var path = @"/App_Data/usersdata.xml";
            XmlSerializerHelper xmlHelper = new XmlSerializerHelper(Server.MapPath(path));
            userModels.AddRange(xmlHelper.Deserialize<List<UserModel>>());
            var userinfo = userModels.Where(o => o.UserName == userName && o.PassWord == passWord).FirstOrDefault();//查找随机码
            if (userinfo!=null)
            {
                statu = tfa.ValidateTwoFactorPIN(userinfo.AccountSecretKey, code);
                if (statu)
                {
                    result = "登录成功";
                }
                else
                {
                    result = "动态码错误";
                }
            }
            else
            {
                result = "用户名或密码错误";
            }
            
            return Json(new { msg = result, statu = statu }, JsonRequestBehavior.AllowGet);
        }


    }
}
