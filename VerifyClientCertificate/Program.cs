using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace VerifyClientCertificate
{
    class Program
    {

        private const string CERT_FILE_NAME = @"parental-controls.api.telstra.com.cer";
        private const string CERT_COMMON_NAME = "parental-controls.api.telstra.com";

        static void Main(string[] args)
        {
            Console.WriteLine(Base64Decode(certString));

            // GetClientCertificateFromDisk();

            //Console.WriteLine(DecodeCert());

            //var cert = GetClientCertificate();

            //Console.WriteLine($"Issuer Name: {cert.GetIssuerName()} \r\n Name: {cert.GetName()}\r\n serial number: {cert.SerialNumber}\r\n");

            //ValidateCert2();

            //var y = cert.Verify();

            Console.Read();

        }


        public static string DecodeCert()
        {



            var content = File.ReadAllText(CERT_FILE_NAME);
            return Base64Decode(content);

        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }


        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        private static X509Certificate2 GetClientCertificateFromDisk()
        {
            string Certificate = CERT_FILE_NAME;

            X509Certificate2 cert = new X509Certificate2();

            cert.Import(Certificate);

            var exported = cert.Export(X509ContentType.Pfx, "w0nt0k");
            var base64 = Convert.ToBase64String(exported);

            Console.WriteLine(Base64Decode(base64));


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


        private const string certString = "MIIHqTCCBpGgAwIBAgITIAAM4ctizn/8Bmt/EAAAAAzhyzANBgkqhkiG9w0BAQUFADCBgTETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB3RlbHN0cmExEzARBgoJkiaJk/IsZAEZFgNkaXIxFDASBgoJkiaJk/IsZAEZFgRjb3JlMSYwJAYDVQQDEx1UZWxzdHJhIEFEIE9iamVjdHMgU0hBMSBDQSBHMjAeFw0xODAyMDIwNDMxNDVaFw0xOTAyMDIwNDMxNDVaMIGHMQswCQYDVQQGEwJBVTEMMAoGA1UECBMDTlNXMQ8wDQYDVQQHEwZTeWRuZXkxEDAOBgNVBAoTB1RlbHN0cmExGzAZBgNVBAsTEkx5YXNoZW5rbyBPcmcgVW5pdDEqMCgGA1UEAxMhcGFyZW50YWwtY29udHJvbHMuYXBpLnRlbHN0cmEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA09JfU0wDCTiapod/6dM+DzOo5uK0cpxld9doyQgju/wW5lturhPBpN2fZPZAl5VyGdurf2E7i8EdJSW0HeEnq2M12SXlfY+DRMlPQy9+OmE8imbQHjjCxFdt3r1R2BWtcdLP44eYhqU+bjuJUR4XLrIdwSmzoLkVjAaaPS/mNM6D0kuFbSeRdH/vnwV3VxvIAl1uJAnm2LmywJ6QJyfIVVXU2rl7CSvJDmPQg6Uo9hZqdJp/18310tx3lrUPBTZpty8IfM04BS6HmLQ+sMDWNr+FZlrqU1LuKjCI1grxBqOY1iSpUpVJmSiwm4FtojxrVQKn+gBBrUp6O0vxKh0RFQIDAQABo4IEEDCCBAwwHQYDVR0OBBYEFJANuZ1ziE4a+zuOYSbKYROLpJenMB8GA1UdIwQYMBaAFFfAmaEWFy3MuZLQJ5DZjrNBLPNCMIIBTgYDVR0fBIIBRTCCAUEwggE9oIIBOaCCATWGgd9sZGFwOi8vL0NOPVRlbHN0cmElMjBBRCUyME9iamVjdHMlMjBTSEExJTIwQ0ElMjBHMixDTj1XU0NBUzAxMTMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y29yZSxEQz1kaXIsREM9dGVsc3RyYSxEQz1jb20/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50hlFodHRwOi8vdGVsc3RyYS1jcmwucGtpLnRlbHN0cmEuY29tLmF1L1RlbHN0cmElMjBBRCUyME9iamVjdHMlMjBTSEExJTIwQ0ElMjBHMi5jcmwwggGCBggrBgEFBQcBAQSCAXQwggFwMIHVBggrBgEFBQcwAoaByGxkYXA6Ly8vQ049VGVsc3RyYSUyMEFEJTIwT2JqZWN0cyUyMFNIQTElMjBDQSUyMEcyLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNvcmUsREM9ZGlyLERDPXRlbHN0cmEsREM9Y29tP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MF0GCCsGAQUFBzAChlFodHRwOi8vdGVsc3RyYS1wa2kucGtpLnRlbHN0cmEuY29tLmF1L1RlbHN0cmElMjBBRCUyME9iamVjdHMlMjBTSEExJTIwQ0ElMjBHMi5jcnQwNwYIKwYBBQUHMAGGK2h0dHA6Ly90ZWxzdHJhLW9jc3AucGtpLnRlbHN0cmEuY29tLmF1L29jc3AwCwYDVR0PBAQDAgWgMD0GCSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCITUjiKC7d9ThfWDGILGvFyFh7stfoGgoz6Bm7ACAgFkAgECMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAnBgkrBgEEAYI3FQoEGjAYMAoGCCsGAQUFBwMBMAoGCCsGAQUFBwMCMF4GA1UdIARXMFUwUwYMKwYBBAGIQAQbAQEBMEMwQQYIKwYBBQUHAgEWNWh0dHA6Ly90ZWxzdHJhLXBraS5wa2kudGVsc3RyYS5jb20uYXUvVGVsc3RyYUNQUy5wZGYAMA0GCSqGSIb3DQEBBQUAA4IBAQCNlINzS54Ngz5BYYK5TNIVyPanj47f+0NBVO7+UO4t4YbI3+NFVUxH1MMBZ9QObsSJsGSdHl1xUZCiOQiOa9XfHdujzeh38IJjUV15bmgdeNY6gLXf8xI2+SgEQsWGWiRSYi7ve+cxzKN9WaVwH0KUfG0943Qjw8PXBOPO8kbC/2Mu9xb5ksWkGlPkrZ9Ea0CGTX0YZWxqniePZPExYOAM2khbMtvGJtq8lXzeP554qT9+SNPXvjgV08HKhIK0fuXuKEqq0lTncR1/fwvB0JZ0rT5AB/m+jMzs7pgKLDt0ZS5gu45WnkhKFnapfusb2ph3vwhZ9a/U+/ASQyUa0AJe";



    }
}
