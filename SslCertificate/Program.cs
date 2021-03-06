﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Selectors;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SslCertificate
{
    class Program
    {
        static void Main(string[] args)
        {
            SignASignature();
            //ListRootCertificates(false);

            //Debug.WriteLine("**************** Personal *******************");

            //ListRootCertificates(true);

            //RunClientCertValidation();

            //CompactClientCertValidation();
        }


        static byte[] Sign(string text, string certSubject)

        {

            // Access Personal (MY) certificate store of current user

            X509Store my = new X509Store(StoreName.Root, StoreLocation.CurrentUser);

            my.Open(OpenFlags.ReadOnly);


            // Find the certificate we'll use to sign

            RSACryptoServiceProvider csp = null;

            foreach (X509Certificate2 cert in my.Certificates)

            {

                if (cert.Subject.Contains(certSubject))

                {

                    // We found it.

                    // Get its associated CSP and private key

                    csp = (RSACryptoServiceProvider)cert.PrivateKey;

                }

            }

            if (csp == null)

            {

                throw new Exception("No valid cert was found");

            }


            // Hash the data

            SHA1Managed sha1 = new SHA1Managed();

            UnicodeEncoding encoding = new UnicodeEncoding();

            byte[] data = encoding.GetBytes(text);

            byte[] hash = sha1.ComputeHash(data);


            // Sign the hash

            return csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));

        }


        static bool Verify(string text, byte[] signature, string certPath)

        {

            // Load the certificate we'll use to verify the signature from a file

            X509Certificate2 cert = new X509Certificate2(certPath);

            // Note:

            // If we want to use the client cert in an ASP.NET app, we may use something like this instead:

            // X509Certificate2 cert = new X509Certificate2(Request.ClientCertificate.Certificate);


            // Get its associated CSP and public key

            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;


            // Hash the data

            SHA1Managed sha1 = new SHA1Managed();

            UnicodeEncoding encoding = new UnicodeEncoding();

            byte[] data = encoding.GetBytes(text);

            byte[] hash = sha1.ComputeHash(data);


            // Verify the signature with the hash

            return csp.VerifyHash(hash, CryptoConfig.MapNameToOID("SHA1"), signature);

        }


        static void SignASignature()

        {

            // Usage sample

            try

            {

                // Sign text

                byte[] signature = Sign("Test", "CN=RootCertificate");


                // Verify signature. Testcert.cer corresponds to "cn=my cert subject"

                if (Verify("Test", signature, @"RootCertificate.cer"))

                {

                    Console.WriteLine("Signature verified");

                }

                else

                {

                    Console.WriteLine("ERROR: Signature not valid!");

                }

            }

            catch (Exception ex)

            {

                Console.WriteLine("EXCEPTION: " + ex.Message);

            }

            Console.ReadKey();

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
