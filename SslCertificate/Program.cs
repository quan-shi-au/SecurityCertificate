using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Selectors;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SslCertificate
{
    class Program
    {
        static void Main(string[] args)
        {
            //ListRootCertificates(false);

            //Debug.WriteLine("**************** Personal *******************");

            //ListRootCertificates(true);

            //RunClientCertValidation();

            CompactClientCertValidation();
        }

        static void ListRootCertificates(bool isPersonal)
        {
            X509Store userCaStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            if (isPersonal)
                userCaStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = userCaStore.Certificates;
                foreach (X509Certificate2 cert in certificatesInStore)
                {
                    Debug.WriteLine(cert.GetExpirationDateString());
                    Debug.WriteLine(cert.Issuer);
                    Debug.WriteLine(cert.GetEffectiveDateString());
                    Debug.WriteLine(cert.GetNameInfo(X509NameType.SimpleName, true));
                    Debug.WriteLine(cert.HasPrivateKey);
                    Debug.WriteLine(cert.SubjectName.Name);
                    Debug.WriteLine("-----------------------------------");
                }
            }
            finally
            {
                userCaStore.Close();
            }
        }

        private static void RunClientCertValidation()
        {
            X509Store userCaStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = userCaStore.Certificates;
                X509Certificate2Collection findResult = certificatesInStore.Find(X509FindType.FindBySubjectName, "localtestclientcert", true);
                foreach (X509Certificate2 cert in findResult)
                {
                    X509Chain chain = new X509Chain();
                    X509ChainPolicy chainPolicy = new X509ChainPolicy()
                    {
                        RevocationMode = X509RevocationMode.Online,
                        RevocationFlag = X509RevocationFlag.EntireChain
                    };
                    chain.ChainPolicy = chainPolicy;
                    if (!chain.Build(cert))
                    {
                        foreach (X509ChainElement chainElement in chain.ChainElements)
                        {
                            foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                            {
                                Debug.WriteLine(chainStatus.StatusInformation);
                            }
                        }
                    }
                }
            }
            finally
            {
                userCaStore.Close();
            }
        }

        private static void CompactClientCertValidation()
        {
            X509Store userCaStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = userCaStore.Certificates;
                X509Certificate2Collection findResult = certificatesInStore.Find(X509FindType.FindBySubjectName, "localtestclientcert", true);
                foreach (X509Certificate2 cert in findResult)
                {
                    X509CertificateValidator chainTrustValidator = X509CertificateValidator.ChainTrust;
                    try
                    {
                        chainTrustValidator.Validate(cert);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(ex.Message);
                    }
                }
            }
            finally
            {
                userCaStore.Close();
            }
        }

    }
}
