using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace VerifyClientCertificate
{
    class Program
    {

        private const string CERT_FILE_NAME = @"parental-controls.api.telstra.com.cer";
        private const string CERT_COMMON_NAME = "mylocalsite.local";

        static void Main(string[] args)
        {
            var cert = GetClientCertificate();

            ValidateCert2();

            var y = cert.Verify();

            Console.Read();

        }

        private static X509Certificate2 GetClientCertificateFromDisk()
        {
            string Certificate = CERT_FILE_NAME;

            X509Certificate2 cert = new X509Certificate2();

            cert.Import(Certificate);
            return cert;
        }

        private static X509Certificate2 GetClientCertificate()
        {
            // ValidateCert();
            X509Store userCaStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = userCaStore.Certificates;
                X509Certificate2Collection findResult = certificatesInStore.Find(X509FindType.FindBySubjectName, CERT_COMMON_NAME, false);
                X509Certificate2 clientCertificate = null;
                if (findResult.Count == 1)
                {
                    clientCertificate = findResult[0];
                }
                else
                {
                    return null;
                }

                var vvv = clientCertificate.Verify();
                return clientCertificate;
            }
            catch
            {
                return null;
            }
            finally
            {
                userCaStore.Close();
            }
        }

        private static bool ValidateCert(X509Certificate2 cert)
        {


            try
            {

                X509Chain chain = new X509Chain();
                X509ChainPolicy chainPolicy = new X509ChainPolicy()
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    RevocationFlag = X509RevocationFlag.EntireChain
                };
                chain.ChainPolicy = chainPolicy;
                if (!chain.Build(cert))
                {
                    return false;
                }

                return true;

            }
            catch
            {
                return false;
            }
        }

        private static void ValidateCert2()
        {
            X509Store userCaStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = userCaStore.Certificates;
                X509Certificate2Collection findResult = certificatesInStore.Find(X509FindType.FindBySubjectName, CERT_COMMON_NAME, false);
                foreach (X509Certificate2 cert in findResult)
                {


                    X509Chain chain = new X509Chain();
                    X509ChainPolicy chainPolicy = new X509ChainPolicy()
                    {
                        RevocationMode = X509RevocationMode.NoCheck,
                        RevocationFlag = X509RevocationFlag.EntireChain
                    };
                    chain.ChainPolicy = chainPolicy;
                    if (!chain.Build(cert))
                    {
                        foreach (X509ChainElement chainElement in chain.ChainElements)
                        {
                            foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                            {

                            }
                        }
                    }


                    X509CertificateValidator chainTrustValidator = X509CertificateValidator.ChainTrust;
                    try
                    {
                        chainTrustValidator.Validate(cert);

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex);

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
