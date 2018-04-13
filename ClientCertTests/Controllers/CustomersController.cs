using ClientCertTests.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Web.Http;

namespace ClientCertTests.Controllers
{
    public class CustomersController : ApiController
    {
        public IHttpActionResult Get()
        {
            X509Certificate2 clientCertInRequest = RequestContext.ClientCertificate;
            //X509Certificate2 clientCertInRequest = Request.GetClientCertificate();
            if (clientCertInRequest != null)
            {
                IList<Customer> customers = new List<Customer>();
                customers.Add(new Customer() { Name = "Nice customer", Address = "USA", Telephone = "123345456" });
                customers.Add(new Customer() { Name = "Good customer", Address = "UK", Telephone = "9878757654" });
                customers.Add(new Customer() { Name = "Awesome customer", Address = "France", Telephone = "34546456" });
                return Ok<IList<Customer>>(customers);
            }
            AuthenticationHeaderValue authHeaderValue = new AuthenticationHeaderValue("ClientCert");
            return Unauthorized(authHeaderValue);
        }
    }
}
