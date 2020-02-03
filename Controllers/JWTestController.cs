using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CRISP.Common.Certificates;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace JWTest.Controllers
{
    [Route("api")]
    public class JWTestController : Controller
    {
        IProvideCerts _certProvider;
        public JWTestController(IProvideCerts certProvider)
        {
            _certProvider = certProvider;

            // used strictly for debugging. DO NOT INCLUDE IN DEVELOPMENT CODE
            IdentityModelEventSource.ShowPII = true;
        }


        [HttpGet, Route("token")]
        public string GetToken()
        {
            X509Certificate2 signingKey = _certProvider.GetCertByThumbprint("3592f8aa1998906ff1ddd397b7a8e8cb7dbc484d");

            var handler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = "you",
                Issuer = "me",
                Subject = new ClaimsIdentity(new List<Claim> {
                    new Claim("Custom", "text value")}),
                EncryptingCredentials = new EncryptingCredentials(
                    key: new X509SecurityKey(signingKey),
                    alg: SecurityAlgorithms.RsaOAEP,
                    enc: SecurityAlgorithms.Aes256CbcHmacSha512),
            };

            return handler.CreateEncodedJwt(tokenDescriptor);
        }

        [HttpPost, Route("token")]
        public void ReadToken([FromQuery] string token)
        {
            X509Certificate2 signingKey = _certProvider.GetCertByThumbprint("3592f8aa1998906ff1ddd397b7a8e8cb7dbc484d");
            var handler = new JwtSecurityTokenHandler();
            var claimsPrincipal = handler.ValidateToken(
                token,
                new TokenValidationParameters
                {
                    ValidAudience = "you",
                    ValidIssuer = "me",
                    RequireSignedTokens = false,
                    TokenDecryptionKey = new X509SecurityKey(signingKey)
                },
                out SecurityToken securityToken);
        }
    }
}