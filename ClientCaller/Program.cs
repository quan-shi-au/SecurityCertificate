using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ClientCaller
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                X509Certificate2 clientCert = GetClientCertificate();
                WebRequestHandler requestHandler = new WebRequestHandler();
                requestHandler.ClientCertificates.Add(clientCert);

                HttpClient client = new HttpClient(requestHandler)
                {
                    BaseAddress = new Uri("https://okapi.wontokone.com/v1/internal/notify-wontok/event/")
                };

                HttpResponseMessage response = client.GetAsync("customers").Result;
                response.EnsureSuccessStatusCode();
                string responseContent = response.Content.ReadAsStringAsync().Result;
                Console.WriteLine(responseContent);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception while executing the test code: {0}", ex.Message);
            }
            Console.ReadKey();
        }

        private static X509Certificate2 GetClientCertificate()
        {
            X509Store userCaStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificatesInStore = userCaStore.Certificates;
                X509Certificate2Collection findResult = certificatesInStore.Find(X509FindType.FindBySubjectName, "localtestclientcert", true);
                X509Certificate2 clientCertificate = null;
                if (findResult.Count == 1)
                {
                    clientCertificate = findResult[0];
                }
                else
                {
                    throw new Exception("Unable to locate the correct client certificate.");
                }
                return clientCertificate;
            }
            catch
            {
                throw;
            }
            finally
            {
                userCaStore.Close();
            }
        }

    }

}
