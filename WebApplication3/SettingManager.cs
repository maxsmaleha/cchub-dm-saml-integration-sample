using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Util;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Web.Helpers;
using WebApplication3.Models;

namespace WebApplication3
{
    public class SettingManager
    {

        private static SettingManager _instance;
        private static readonly object syncRoot = new object();

        public Saml2Configuration Configuration;
        public List<RelyingParty> RelyingParties;

        public static void Init()
        {

            lock (syncRoot)
            {
                if (_instance == null)
                {
                    AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;

                    _instance = new SettingManager
                    {
                        Configuration = new Saml2Configuration
                        {
                            Issuer = ConfigurationManager.AppSettings["Saml2:Issuer"],
                            SingleSignOnDestination = new Uri(ConfigurationManager.AppSettings["Saml2:SingleSignOnDestination"]),
                            SingleLogoutDestination = new Uri(ConfigurationManager.AppSettings["Saml2:SingleLogoutDestination"]),
                            SignatureAlgorithm = ConfigurationManager.AppSettings["Saml2:SignatureAlgorithm"],
                            SigningCertificate = CertificateUtil.Load(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ConfigurationManager.AppSettings["Saml2:SigningCertificateFile"]), ConfigurationManager.AppSettings["Saml2:SigningCertificatePassword"]),

                            CertificateValidationMode = (X509CertificateValidationMode)Enum.Parse(typeof(X509CertificateValidationMode), ConfigurationManager.AppSettings["Saml2:CertificateValidationMode"]),
                            RevocationMode = (X509RevocationMode)Enum.Parse(typeof(X509RevocationMode), ConfigurationManager.AppSettings["Saml2:RevocationMode"]),
                            AudienceRestricted = true,
                            AllowedIssuer = ConfigurationManager.AppSettings["Saml2:Issuer"]
                        },
                        RelyingParties = new List<RelyingParty>(),
                    };

                    _instance.Configuration.AllowedAudienceUris.Add(ConfigurationManager.AppSettings["Saml2:Issuer"]);

                    _instance.RelyingParties.Add(new RelyingParty() { Metadata = ConfigurationManager.AppSettings["Saml2:RelyingPartyMetadata"] });
                }
            }
        }

        public static SettingManager GetInstance()
        {
            lock (syncRoot)
            {
                if (_instance == null)
                {
                    throw new Exception(
                        "Setting manager is not initiated! Use SettingManager.Init(params..) before GetInstance()");
                }

                return _instance;
            }
        }

    }
}