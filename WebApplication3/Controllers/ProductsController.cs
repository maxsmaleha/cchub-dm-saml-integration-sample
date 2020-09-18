using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using WebApplication3.Filters;
using WebApplication3.Models;

namespace WebApplication3.Controllers
{
    [RoutePrefix("api/products")]
    public class ProductsController : ApiController
    {

        [ApiKeyAuthorizationFilter]
        [HttpGet]
        [Route("")]
        public List<ProductModel> GetAll()
        {
            return TestProducts.Products;
        }
    }
}
