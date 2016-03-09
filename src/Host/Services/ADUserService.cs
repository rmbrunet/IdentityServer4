using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
//using System.DirectoryServices;
//using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Threading.Tasks;
/*
namespace Host.Services
{
    public class ADUserService 
    {
        static class ADAttributes
        {
            public static string SamAccountName = "samaccountname";
            public static string Mail = "mail";
            public static string UserGroup = "usergroup";
            public static string DisplayName = "displayname";
            public static string Department = "department";
            public static string StreetAddress = "streetAddress";
            public static string Phone = "telephoneNumber";
            public static string State = "st";
            public static string City = "l";
            public static string Zip = "postalCode";
            public static string Surname = "sn";
            public static string Givenname = "givenName";
        }

        Func<string, string> _ldapConnectionDelegate; //Delegate that receives the domain and returns the LDAP connection string.

        ILogger _logger;

        string _connection;

        public ADUserService(string connection, Func<string, string> ldapConnectionDelegate, ILogger logger)
        {
            _ldapConnectionDelegate = ldapConnectionDelegate;
            _logger = logger;
            _connection = connection;
        }

        public Task AuthenticateLocalAsync(LocalAuthenticationContext context)
        {
            bool isUserValid = false;

            //context.SignInMessage.ClientId

            string username = context.UserName;

            string[] u = username.ToLower().Split('\\');

            string domain = u[0]; //username assumed to be in the foem domain\user
            string uname = u[1];

            _logger.LogInformation("AUTHENTICATION ATTEMPT for user {username}", username);

            using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, domain))
            {
                isUserValid = pc.ValidateCredentials(uname, context.Password, ContextOptions.Negotiate);
            }

            if (isUserValid)
            {
                _logger.LogInformation("AUTHENTICATION SUCCESS for user {username}", username);
                context.AuthenticateResult = new AuthenticateResult(subject: username.ToLower(), name: username, claims: null, identityProvider: Constants.BuiltInIdentityProvider, authenticationMethod: Constants.AuthenticationMethods.Password);
            }
            else {
                _logger.LogWarning("AUTHENTICATION FAILURE for user {username}", username);
            }

            return Task.FromResult(0);
        }

        public Task SignOutAsync(SignOutContext context)
        {
            return Task.FromResult(0);
        }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            List<System.Security.Claims.Claim> claims = null;

            //context.Client.ClientId

            string subject = context.Subject.GetSubjectId();

            _logger.LogInformation("GET_PROFILE ATTEMPT for user {subject}", subject);

            SearchResult result = findUser(subject, true);

            if (result != null &&
                result.Properties.Contains(ADAttributes.Mail) &&
                result.Properties.Contains(ADAttributes.DisplayName))
            {

                claims = new List<Claim>();

                claims.Add(new Claim(Constants.ClaimTypes.Subject, subject));
                claims.Add(new Claim(Constants.ClaimTypes.Email, (String)result.Properties[ADAttributes.Mail][0]));
                claims.Add(new Claim(Constants.ClaimTypes.Name, (String)result.Properties[ADAttributes.DisplayName][0]));

                if (result.Properties.Contains(ADAttributes.Surname))
                    claims.Add(new Claim(Constants.ClaimTypes.FamilyName, (String)result.Properties[ADAttributes.Surname][0]));

                if (result.Properties.Contains(ADAttributes.Givenname))
                    claims.Add(new Claim(Constants.ClaimTypes.GivenName, (String)result.Properties[ADAttributes.Givenname][0]));

                //Is there an address?
                if (result.Properties.Contains(ADAttributes.State)
                    && result.Properties.Contains(ADAttributes.StreetAddress)
                    && result.Properties.Contains(ADAttributes.City)
                    && result.Properties.Contains(ADAttributes.Zip))
                {

                    string state = (String)result.Properties[ADAttributes.State][0];
                    string street = (String)result.Properties[ADAttributes.StreetAddress][0];
                    string city = (String)result.Properties[ADAttributes.City][0];
                    string zip = (String)result.Properties[ADAttributes.Zip][0];

                    string address = string.Format("{0}, {1}, {2} {3}", street, city, state, zip);
                    claims.Add(new Claim(Constants.ClaimTypes.Address, address));
                }

                // Add Roles...
                claims.Add(new Claim(Constants.ClaimTypes.Role, "user"));

                if (!context.AllClaimsRequested)
                {
                    claims = claims.Where(x => context.RequestedClaimTypes.Contains(x.Type)).ToList();
                }
            }

            context.IssuedClaims = claims;

            return Task.FromResult(0);
        }

        public Task IsActiveAsync(IsActiveContext context)
        {

            var user = findUser(context.Subject.GetSubjectId(), false);

            if (user != null)
            {

                if (context.ClientId != null)
                {

                }

                context.IsActive = true;
            }

            return Task.FromResult(0);
        }

        //string[] getRoles() {
        //    string sql = "SELECT * FROM SWS_STS.IdentityServer.ClientUsers WHERE";

        //}

        System.DirectoryServices.SearchResult findUser(string subject, bool verbose)
        {
            string[] a = subject.Split('\\');

            string domain = a[0];
            string username = a[1];

            string node = _ldapConnectionDelegate(domain);

            _logger.LogInformation("FIND_USER ATTEMPT for user {subject}", subject);


            using (DirectoryEntry searchRoot = new DirectoryEntry(node))
            {
                using (DirectorySearcher search = new DirectorySearcher(searchRoot))
                {

                    search.Filter = string.Format("(&(objectClass=user)(objectCategory=person)(SAMAccountName={0}))", username);

                    if (verbose)
                    {
                        //search.PropertiesToLoad.Add( Constants.ADAttributes.SamAccountName );
                        search.PropertiesToLoad.Add(ADAttributes.Mail);
                        search.PropertiesToLoad.Add(ADAttributes.UserGroup);
                        search.PropertiesToLoad.Add(ADAttributes.DisplayName);
                        search.PropertiesToLoad.Add(ADAttributes.Surname);
                        search.PropertiesToLoad.Add(ADAttributes.Givenname);
                        search.PropertiesToLoad.Add(ADAttributes.Department);
                        search.PropertiesToLoad.Add(ADAttributes.StreetAddress);
                        search.PropertiesToLoad.Add(ADAttributes.Phone);
                        search.PropertiesToLoad.Add(ADAttributes.State);
                        search.PropertiesToLoad.Add(ADAttributes.City);
                        search.PropertiesToLoad.Add(ADAttributes.Zip);
                    }
                    _logger.LogInformation("BEFORE FindOne");
                    try
                    {
                        return search.FindOne();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error for Subject {subject}", subject);
                        throw;
                    }
                }
            }
        }


    }
}
*/