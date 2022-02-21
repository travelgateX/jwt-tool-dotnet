﻿using System.Collections.Generic;
using System;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace DotnetJwtTools
{
    public class JwtTools
    {
        #region PUBLIC KEY AUTH0
        private static string CNST_PUBLIC_KEY = "-----BEGIN CERTIFICATE-----MIIC6DCCAdCgAwIBAgIJHWgMlgDhBwcLMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEHh0Zy5ldS5hdXRoMC5jb20wHhcNMTYxMjA4MjIyMjQyWhcNMzAwODE3MjIyMjQyWjAbMRkwFwYDVQQDExB4dGcuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwClsy/seBHmPeYm+Y53UZJG4vBGdRkG9boqkIp9E4U0kE34BDYm/qjJm/hng+sJjyHwGTlgI/2Vv9aDM1cd2TgXuUN4DvNOXsw0UEtM42HFiGoaFQupNbYXHJbHVse3ai8RtQoH1uf3pT21GMw8VdewfNfD7gjd465t0CaPCEUcJzwIJBxdCGOoxmUO6XlrBfy4amJndLrzmmKncJ4FbLMYGuqvjpp/14St2KPobPDfOSlorb50Don0mlvFey5wNW49ISaOYtqOQqZNFcWgEiNXelneVWL1Lnwbaigp79jWN0clikGQ1/+3izMC2+uEY6J4GLVHO9NXivQXrroKYfQIDAQABoy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQYLV04ndhtuHsYaWyFL3HEmVRJ+jANBgkqhkiG9w0BAQUFAAOCAQEAogs6rdio/sJrbXbizLEiHo4dEg3vq5WtkdgbDWmOqA0C6NE4JGDI+C52AJ3GJFYIVG+6uMCClDNWWJyXTbwzrBgGSeebZJyYGa/HzJDUkSOXzc6b6nBV3+seTIUOnCNZLNDUHwIO9xJMs1yadQ0v9guXrFft7LN1V3pFM/4B3RyEQtWsXjdjD+xWazlxcWxEAZaWLdDdfs5KOT8xi7k3O+UpjeE+zjDXq+hFM9hK46xuTAd9USJYpzKG8dBcaHZ9e7JVxiINww4KTrO0l9LqUrIeMngK0MlS+DGog7S95ul5yX6XwYFy4FS35fh/qTAEg1jjwJ+oI+LaYwyNKnwl5g==-----END CERTIFICATE-----";
        private static byte[] CNST_PK = Convert.FromBase64String(@"MIIC6DCCAdCgAwIBAgIJHWgMlgDhBwcLMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEHh0Zy5ldS5hdXRoMC5jb20wHhcNMTYxMjA4MjIyMjQyWhcNMzAwODE3MjIyMjQyWjAbMRkwFwYDVQQDExB4dGcuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwClsy/seBHmPeYm+Y53UZJG4vBGdRkG9boqkIp9E4U0kE34BDYm/qjJm/hng+sJjyHwGTlgI/2Vv9aDM1cd2TgXuUN4DvNOXsw0UEtM42HFiGoaFQupNbYXHJbHVse3ai8RtQoH1uf3pT21GMw8VdewfNfD7gjd465t0CaPCEUcJzwIJBxdCGOoxmUO6XlrBfy4amJndLrzmmKncJ4FbLMYGuqvjpp/14St2KPobPDfOSlorb50Don0mlvFey5wNW49ISaOYtqOQqZNFcWgEiNXelneVWL1Lnwbaigp79jWN0clikGQ1/+3izMC2+uEY6J4GLVHO9NXivQXrroKYfQIDAQABoy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQYLV04ndhtuHsYaWyFL3HEmVRJ+jANBgkqhkiG9w0BAQUFAAOCAQEAogs6rdio/sJrbXbizLEiHo4dEg3vq5WtkdgbDWmOqA0C6NE4JGDI+C52AJ3GJFYIVG+6uMCClDNWWJyXTbwzrBgGSeebZJyYGa/HzJDUkSOXzc6b6nBV3+seTIUOnCNZLNDUHwIO9xJMs1yadQ0v9guXrFft7LN1V3pFM/4B3RyEQtWsXjdjD+xWazlxcWxEAZaWLdDdfs5KOT8xi7k3O+UpjeE+zjDXq+hFM9hK46xuTAd9USJYpzKG8dBcaHZ9e7JVxiINww4KTrO0l9LqUrIeMngK0MlS+DGog7S95ul5yX6XwYFy4FS35fh/qTAEg1jjwJ+oI+LaYwyNKnwl5g==");
        #endregion

        public bool IsError = false;
        public string Error = null;
        private const string CNST_ALL = "all";
        private const string CNST_CRUD = "crud";
        private const string CNST_ADMIN = "a";
        private const string CNST_TEAM = "TEAM";
        private const string CNST_PRODUCT = "PRODUCT";
        //---------- FETCH NEEDED ----------------//
        private const string CNST_FETCH_NEED = "https://travelgatex.com/fetch_needed";

        //---------- BASIC PERMISSIONS -----------//
        private const string CNST_CREATE = "c";
        private const string CNST_UPDATE = "u";
        private const string CNST_DELETE = "d";
        private const string CNST_READ = "r";

        // Product --> Object --> Permission --> Groups ... Api -> Operation -> read, Update -> Organizations..
        public Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>> Permissions { get; set; }
        public bool IsAdmin { get; set; }
        public string UserEmail { get; set; }
        public string UserBearer { get; set; }
        public HashSet<string> ExtraNode { get; set; }
        public HashSet<string> IamProducts { get; set; }
        public bool IsBearer { get; set; } = false;
        public Dictionary<string, GroupTree> PTree { get; set; }

        public JwtTools(string pBearer, string pAdminGroup, string pJwtIamName, string pExtraValuePath = null)
        {
            IsBearer = true;
            UserBearer = pBearer;
            _NewPermissionTable(pBearer, pAdminGroup, pJwtIamName, pExtraValuePath);
        }

        public JwtTools(string pBearer, string pJwtIamName, string pExtraValuePath = null)
        {
            IsBearer = true;
            UserBearer = pBearer;
            _NewPermissionTable(pBearer, string.Empty, pJwtIamName, pExtraValuePath);
        }

        public JwtTools()
        {
        }

        /// <summary>
        /// Create the PermissionTable and saves it
        /// </summary>
        /// <param name="pBearer"></param>
        /// <param name="pAdminGroup"></param>
        /// <param name="pJwtIamName"></param>
        /// <remarks></remarks>
        /// <returns></returns>
        private void _NewPermissionTable(string pBearer, string pAdminGroup, string pJwtIamName, string pExtraValuePath)
        {
            try
            {
                bool jwtValidated = _ValidateJwtToken(pBearer);

                if (!jwtValidated)
                {
                    IsError = true;
                    Permissions = null;
                    Error = "Invalid Bearer";
                }

                string strJwt = _ExtractClaims(pBearer, pJwtIamName, pExtraValuePath);

                if (!string.IsNullOrEmpty(strJwt))
                {
                    Jwt jwt = JsonConvert.DeserializeObject<Jwt>(strJwt);

                    IsAdmin = false;
                    Permissions = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>>();
                    PTree = new Dictionary<string, GroupTree>();
                    _BuildPermissions(new List<Jwt> { jwt }, PTree, pAdminGroup);
                }
            }
            catch (Exception e)
            {
                Error = e.Message;
                IsError = true;
                Permissions = null;
            }
        }


        #region JWT Validation
        private static bool _ValidateJwtToken(string pJwt)
        {
            //X509Certificate2 DefaultCert_Public_2048 = new X509Certificate2(System.Text.Encoding.ASCII.GetBytes(CNST_PUBLIC_KEY));
            X509Certificate2 DefaultCert_Public_2048 = new X509Certificate2(CNST_PK);
            X509SecurityKey DefaultX509Key_Public_2048 = new X509SecurityKey(DefaultCert_Public_2048);

            //SigningCredentials credentials = new SigningCredentials(DefaultX509Key_Public_2048, SecurityAlgorithms.RsaSha256Signature);

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateActor = false,
                ValidateLifetime = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = DefaultX509Key_Public_2048
            };

            SecurityToken validatedToken;
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            ClaimsPrincipal claims = handler.ValidateToken(pJwt, validationParameters, out validatedToken);

            if (claims?.Claims?.Count() > 0)
            {
                return true;
            }

            return false;
        }
        #endregion

        //Return the IAM and extravalue claims value
        private string _ExtractClaims(string pJwt, string pJwtIamName, string pExtraValuePath, bool isRecusive = false)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.ReadJwtToken(pJwt);

            bool getExtraValue = !string.IsNullOrEmpty(pExtraValuePath);
            string fetchNeed = null;

            string ret = string.Empty;

            foreach (Claim claim in token.Claims)
            {
                // Check if is fetch needed
                if (claim.Type == CNST_FETCH_NEED)
                    fetchNeed = claim.Value;

                // Get IAM
                if (claim.Type == pJwtIamName)
                    ret = claim.Value;

                // Get Extra Nodes
                if (getExtraValue && claim.Type == pExtraValuePath)
                {
                    if (ExtraNode == null) ExtraNode = new HashSet<string>();
                    if (!ExtraNode.Contains(claim.Value))
                        ExtraNode.Add(claim.Value);
                }

                // Get User Email
                if (claim.Type == "https://travelgatex.com/member_id")
                    UserEmail = claim.Value;
            }

            if (!isRecusive && fetchNeed == "true")
            {
                string newBearer = _GetFullBearer(pJwt);
                ret = _ExtractClaims(newBearer, pJwtIamName, pExtraValuePath, true);
            }


            return ret;
        }

        private string _GetFullBearer(string pBearer)
        {
            const string url = "https://api-iam.travelgatex.com/controller/xquery";
            const string request = "{\"query\":\"query{ admin{ getBearer(){ token adviseMessage{ code description level } } } }\"}";

            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pBearer);

            HttpResponseMessage rs = client.PostAsync(url, new StringContent(request)).GetAwaiter().GetResult();

            string json = rs.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            JObject jObject = JObject.Parse(json);
            string ret = jObject["data"]["admin"]["getBearer"]["token"].ToString();

            return ret;
        }

        /// <summary>
        /// Generates the permissions for a given groups an fill the group trees
        /// </summary>
        /// <param name="pGroups"></param>
        /// <param name="pTree"></param>
        /// <param name="pAdminGroup"></param>
        /// <remarks></remarks>
        /// <returns></returns>
        private void _BuildPermissions(List<Jwt> pGroups, Dictionary<string, GroupTree> pTree, string pAdminGroup)
        {
            if (pGroups == null) return;

            foreach (Jwt group in pGroups)
            {
                //Check if the data is filled
                if (group.GroupCode == null) return;
                if (group.Type == null) return;

                //Add Products to ProductList
                if (group.Type == CNST_PRODUCT)
                {
                    if (IamProducts == null) IamProducts = new HashSet<string>();
                    if (!IamProducts.Contains(group.GroupCode)) IamProducts.Add(group.GroupCode);
                }

                //Fill the tree with the data on the group
                pTree[group.GroupCode] = new GroupTree { Groups = new Dictionary<string, GroupTree>(), GroupType = group.Type };

                //Check the Products
                //if (group.GroupAdditional?.Count > 0) this._ExtractAdditionalGroups(group.GroupAdditional);

                _FillPermissionsFromProducts(group.GroupPermissions, Permissions, group.GroupCode, pAdminGroup, group.Type);

                //Call recursivity
                Dictionary<string, GroupTree> groupTree = pTree[group.GroupCode].Groups;
                _BuildPermissions(group.GroupDescendants, groupTree, pAdminGroup);
            }
        }

        /// <summary>
        /// Check the Permissions in the Group.p nodes and add it in pPermissions
        /// </summary>
        /// <param name="pProducts"></param>
        /// <param name="pPermissions"></param>
        /// <param name="pGroup"></param>
        /// <param name="pAdminGroup"></param>
        /// <remarks></remarks>
        /// <returns></returns>
        private bool _FillPermissionsFromProducts(Dictionary<string, Dictionary<string, List<string>>> pProducts, Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>> pPermissions, string pGroup, string pAdminGroup, string pGroupType)
        {
            if (pProducts == null) return false;
            bool ret = false;

            foreach (KeyValuePair<string, Dictionary<string, List<string>>> objects in pProducts)
            {
                //If we dont have the key, or the key with a null value, we initialize it
                if (!pPermissions.ContainsKey(objects.Key))
                {
                    pPermissions.Add(objects.Key, new Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>());
                }

                if (pPermissions[objects.Key] == null)
                {
                    pPermissions[objects.Key] = new Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>();
                }

                Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>> p = pPermissions[objects.Key];

                if (objects.Value != null)
                {
                    foreach (KeyValuePair<string, List<string>> perms in objects.Value)
                    {
                        Tuple<bool, Dictionary<string, Dictionary<string, HashSet<string>>>> tuple;
                        if (!p.ContainsKey(perms.Key))
                        {
                            p.Add(perms.Key, new Dictionary<string, Dictionary<string, HashSet<string>>>());
                        }

                        tuple = _GetObjects(perms.Value, pGroup, p[perms.Key], pAdminGroup, pGroupType);
                        pPermissions[objects.Key][perms.Key] = tuple.Item2;
                        if (tuple.Item1) ret = true;
                    }
                }
            }
            return ret;
        }

        /// <summary>
        /// Get the permissions of an object and return the permissions and if the user is Admin
        /// </summary>
        /// <param name="pRoles"></param>
        /// <param name="pGroup"></param>
        /// <param name="pP"></param>
        /// <param name="pAdminGroup"></param>
        /// <remarks></remarks>
        /// <returns>A tuple with item1 = is Admin, Item2 = permissions.</returns>
        private Tuple<bool, Dictionary<string, Dictionary<string, HashSet<string>>>> _GetObjects(List<string> pRoles, string pGroup, Dictionary<string, Dictionary<string, HashSet<string>>> pP, string pAdminGroup, string pGroupType)
        {
            bool isAdmin = false;

            foreach (string rol in pRoles)
            {
                foreach (KeyValuePair<string, Dictionary<string, string>> perm in _ExtractPermissions(rol))
                {
                    if (!pP.ContainsKey(perm.Key))
                    {
                        pP.Add(perm.Key, new Dictionary<string, HashSet<string>>());
                    }

                    if (!pP[perm.Key].ContainsKey(pGroup))
                    {
                        //If is a internal team, has permission for all orgs
                        if (pGroupType == CNST_TEAM)
                        {
                            if (!pP[perm.Key].ContainsKey(CNST_ALL))
                                pP[perm.Key].Add(CNST_ALL, null);

                            //Add all products for interal teams
                            if (IamProducts == null) IamProducts = new HashSet<string>();
                            if (!IamProducts.Contains(CNST_ALL)) IamProducts.Add(CNST_ALL);
                        }

                        pP[perm.Key].Add(pGroup, null);
                    }
                }
            }

            if (pAdminGroup == pGroup || pP.ContainsKey(CNST_CREATE) && pP.ContainsKey(CNST_READ) && pP.ContainsKey(CNST_UPDATE) && pP.ContainsKey(CNST_DELETE))
            {
                isAdmin = true;
            }

            return new Tuple<bool, Dictionary<string, Dictionary<string, HashSet<string>>>>(isAdmin, pP);
        }

        /// <summary>
        /// Extracts the permission of a string
        /// </summary>
        /// <param name="pP"></param>
        /// <remarks></remarks>
        /// <returns>A dictionary with the permissions</returns>
        private Dictionary<string, Dictionary<string, string>> _ExtractPermissions(string p)
        {
            bool enabled = false;
            Dictionary<string, Dictionary<string, string>> ret = new Dictionary<string, Dictionary<string, string>>();

            for (int i = 0; i < p.Length; i++)
            {
                switch (p[i])
                {
                    case 'c':
                        ret.Add(CNST_CREATE, new Dictionary<string, string>());
                        break;
                    case 'r':
                        ret.Add(CNST_READ, new Dictionary<string, string>());
                        break;
                    case 'u':
                        ret.Add(CNST_UPDATE, new Dictionary<string, string>());
                        break;
                    case 'd':
                        ret.Add(CNST_DELETE, new Dictionary<string, string>());
                        break;
                    case '1':
                        enabled = true;
                        break;
                    default:
                        ret.Add(p[i].ToString(), new Dictionary<string, string>());
                        break;
                }
            }


            if (enabled)
            {
                if (ret.ContainsKey(CNST_CREATE) && ret.ContainsKey(CNST_READ) && ret.ContainsKey(CNST_UPDATE) && ret.ContainsKey(CNST_DELETE))
                    if (!ret.ContainsKey(CNST_ADMIN)) ret.Add(CNST_ADMIN, new Dictionary<string, string>());

                return ret;
            }

            return new Dictionary<string, Dictionary<string, string>>();
        }

        //private void _ExtractAdditionalGroups(Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>> pGroupAdditional)
        //{
        //    if (this.Permissions == null) this.Permissions = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>>();
        //    string perm = string.Empty;
        //    //for each product
        //    foreach (var groupProd in pGroupAdditional)
        //    {
        //        if (!this.Permissions.ContainsKey(groupProd.Key))
        //            this.Permissions.Add(groupProd.Key, new Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>());

        //        //for each api
        //        foreach (var groupApi in groupProd.Value)
        //        {
        //            if (!this.Permissions[groupProd.Key].ContainsKey(groupApi.Key))
        //                this.Permissions[groupProd.Key].Add(groupApi.Key, new Dictionary<string, Dictionary<string, HashSet<string>>>());

        //            //for each object
        //            foreach (var groupObj in groupApi.Value)
        //            {
        //                //if (!this.Permissions[groupProd.Key][groupApi.Key].ContainsKey(groupObj.Key))
        //                //    this.Permissions[groupProd.Key][groupApi.Key].Add(groupObj.Key, new Dictionary<string, HashSet<string>>());

        //                //foreach permission
        //                foreach (var groupPer in groupObj.Value)
        //                {
        //                    perm = groupPer;
        //                    if (perm == "1a") perm = CNST_ADMIN;

        //                    //add Permission
        //                    if (!this.Permissions[groupProd.Key][groupApi.Key].ContainsKey(perm))
        //                        this.Permissions[groupProd.Key][groupApi.Key].Add(perm, new Dictionary<string, HashSet<string>>());

        //                    if (!this.Permissions[groupProd.Key][groupApi.Key][perm].ContainsKey(groupObj.Key))
        //                        this.Permissions[groupProd.Key][groupApi.Key][perm].Add(groupObj.Key, null);
        //                }
        //            }
        //        }

        //    }
        //}

        /// <summary>
        /// Check if a group have a permision for a product and object 
        /// </summary>
        /// <param name="pProduct"></param>
        /// <param name="pObj"></param>
        /// <param name="pPermission"></param>
        /// <param name="pGroup"></param>
        /// <remarks></remarks>
        /// <returns>A boolean meaning if the group have permission</returns>
        public bool CheckPermission(string pProduct, string pObj, string pPermission, string pGroup, string pOperation = null)
        {
            return CheckPermission(pProduct, pObj, pPermission, new List<string> { pGroup }, pOperation);
        }

        /// <summary>
        /// Check if any of the given groups have a permision for a product and object 
        /// </summary>
        /// <param name="pProduct"></param>
        /// <param name="pObj"></param>
        /// <param name="pPermission"></param>
        /// <param name="pGroups"></param>
        /// <remarks></remarks>
        /// <returns>A boolean meaning if the group have permission</returns>
        public bool CheckPermission(string pProduct, string pObj, string pPermission, List<string> pGroups, string pOperation = null)
        {
            //--- Initial validations
            if (IsAdmin) { return true; }
            if (Permissions == null) return false;
            bool checkOperation = !string.IsNullOrEmpty(pOperation);
            //---

            //Check for concrete product
            if (Permissions.ContainsKey(pProduct))
            {
                //Check for all object
                if (Permissions[pProduct].ContainsKey(CNST_ALL))
                {
                    if (Permissions[pProduct][CNST_ALL].ContainsKey(pPermission))
                    {
                        foreach (string group in pGroups)
                        {
                            //Check if have the group
                            if (Permissions[pProduct][CNST_ALL][pPermission].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                //Check if we have the operationAdded to operations list
                                if (Permissions[pProduct][CNST_ALL][pPermission][group] != null)
                                {
                                    if (Permissions[pProduct][CNST_ALL][pPermission][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        //Check if we have all the groups
                        if (Permissions[pProduct][CNST_ALL][pPermission].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            //Check if we have the operationAdded to operations list
                            if (Permissions[pProduct][CNST_ALL][pPermission][CNST_ALL] != null)
                            {
                                if (Permissions[pProduct][CNST_ALL][pPermission][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }
                    }

                    //Check if we have major permission
                    //We do this always in the case we have more permission than indicated in a operation               
                    foreach (var permission in Permissions[pProduct][CNST_ALL])
                    {
                        //Check if we have the group
                        if (permission.Key.StartsWith(CNST_CRUD) || permission.Key.Equals(CNST_ADMIN))
                        {
                            foreach (string group in pGroups)
                            {
                                //Check if we have the group
                                if (permission.Value.ContainsKey(group))
                                {
                                    if (!checkOperation) return true;

                                    //Check if we have the operationAdded to operations list
                                    if (Permissions[pProduct][CNST_ALL][permission.Key][group] != null)
                                    {
                                        if (Permissions[pProduct][CNST_ALL][permission.Key][group].Contains(pOperation)) return true;
                                    }
                                    //If the hashset of operation is null, we asume we don't filter by operation
                                    else
                                    {
                                        return true;
                                    }
                                }
                            }

                            //Check if we have all
                            if (permission.Value.ContainsKey(CNST_ALL))
                            {
                                if (!checkOperation) return true;

                                //Check if we have the operationAdded to operations list
                                if (Permissions[pProduct][CNST_ALL][permission.Key][CNST_ALL] != null)
                                {
                                    if (Permissions[pProduct][CNST_ALL][permission.Key][CNST_ALL].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }
                    }


                }

                //Check for concrete object
                if (Permissions[pProduct].ContainsKey(pObj))
                {
                    if (Permissions[pProduct][pObj].ContainsKey(pPermission))
                    {
                        foreach (string group in pGroups)
                        {
                            if (Permissions[pProduct][pObj][pPermission].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (Permissions[pProduct][pObj][pPermission][group] != null)
                                {
                                    if (Permissions[pProduct][pObj][pPermission][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }

                            }
                        }

                        if (Permissions[pProduct][pObj][pPermission].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (Permissions[pProduct][pObj][pPermission][CNST_ALL] != null)
                            {
                                if (Permissions[pProduct][pObj][pPermission][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }

                    }
                    else if (Permissions[pProduct][pObj].ContainsKey(CNST_CRUD))
                    {
                        foreach (string group in pGroups)
                        {
                            if (Permissions[pProduct][pObj][CNST_CRUD].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (Permissions[pProduct][pObj][CNST_CRUD][group] != null)
                                {
                                    if (Permissions[pProduct][pObj][CNST_CRUD][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        if (Permissions[pProduct][pObj][CNST_CRUD].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (Permissions[pProduct][pObj][CNST_CRUD][CNST_ALL] != null)
                            {
                                if (Permissions[pProduct][pObj][CNST_CRUD][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }
                    }
                    else if (Permissions[pProduct][pObj].ContainsKey(CNST_ADMIN))
                    {
                        foreach (string group in pGroups)
                        {
                            if (Permissions[pProduct][pObj][CNST_ADMIN].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (Permissions[pProduct][pObj][CNST_ADMIN][group] != null)
                                {
                                    if (Permissions[pProduct][pObj][CNST_ADMIN][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        if (Permissions[pProduct][pObj][CNST_ADMIN].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (Permissions[pProduct][pObj][CNST_ADMIN][CNST_ALL] != null)
                            {
                                if (Permissions[pProduct][pObj][CNST_ADMIN][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            //Check for all product
            if (Permissions.ContainsKey(CNST_ALL))
            {
                //Check for all object
                if (Permissions[CNST_ALL].ContainsKey(CNST_ALL))
                {
                    //Check for all permission
                    if (Permissions[CNST_ALL][CNST_ALL].ContainsKey(pPermission))
                    {
                        foreach (string group in pGroups)
                        {
                            //Check if have the group
                            if (Permissions[CNST_ALL][CNST_ALL][pPermission].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (Permissions[CNST_ALL][CNST_ALL][pPermission][group] != null)
                                {
                                    if (Permissions[CNST_ALL][CNST_ALL][pPermission][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        //Check if have the all
                        if (Permissions[CNST_ALL][CNST_ALL][pPermission].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (Permissions[CNST_ALL][CNST_ALL][pPermission][CNST_ALL] != null)
                            {
                                if (Permissions[CNST_ALL][CNST_ALL][pPermission][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }
                    }

                    //Check if we have major permission
                    foreach (var permission in Permissions[CNST_ALL][CNST_ALL])
                    {
                        if (permission.Key.StartsWith(CNST_CRUD) || permission.Key.Equals(CNST_ADMIN))
                        {
                            foreach (string group in pGroups)
                            {
                                //Check if we have the group
                                if (permission.Value.ContainsKey(group))
                                {
                                    if (!checkOperation) return true;

                                    if (Permissions[CNST_ALL][CNST_ALL][permission.Key][group] != null)
                                    {
                                        if (Permissions[CNST_ALL][CNST_ALL][permission.Key][group].Contains(pOperation)) return true;
                                    }
                                    //If the hashset of operation is null, we asume we don't filter by operation
                                    else
                                    {
                                        return true;
                                    }
                                }
                            }

                            //Check if we have the all
                            if (permission.Value.ContainsKey(CNST_ALL))
                            {
                                if (!checkOperation) return true;

                                if (Permissions[CNST_ALL][CNST_ALL][permission.Key][CNST_ALL] != null)
                                {
                                    if (Permissions[CNST_ALL][CNST_ALL][permission.Key][CNST_ALL].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }
                    }

                }
                //Check for concrete object
                else
                {
                    if (Permissions[CNST_ALL].ContainsKey(pObj))
                    {
                        if (Permissions[CNST_ALL][pObj].ContainsKey(pPermission))
                        {
                            foreach (string group in pGroups)
                            {
                                //Check if we have the group
                                if (Permissions[CNST_ALL][pObj][pPermission].ContainsKey(group))
                                {
                                    if (!checkOperation) return true;

                                    if (Permissions[CNST_ALL][pObj][pPermission][group] != null)
                                    {
                                        if (Permissions[CNST_ALL][pObj][pPermission][group].Contains(pOperation)) return true;
                                    }
                                    //If the hashset of operation is null, we asume we don't filter by operation
                                    else
                                    {
                                        return true;
                                    }
                                }
                            }

                            //Check if we have the all
                            if (Permissions[CNST_ALL][pObj][pPermission].ContainsKey(CNST_ALL))
                            {
                                if (!checkOperation) return true;

                                if (Permissions[CNST_ALL][pObj][pPermission][CNST_ALL] != null)
                                {
                                    if (Permissions[CNST_ALL][pObj][pPermission][CNST_ALL].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        //Check if we have major permission
                        foreach (var permission in Permissions[CNST_ALL][pObj])
                        {
                            if (permission.Key.StartsWith(CNST_CRUD) || permission.Key.Equals(CNST_ADMIN))
                            {
                                foreach (string group in pGroups)
                                {
                                    //Check if we have the group
                                    if (permission.Value.ContainsKey(group))
                                    {
                                        if (!checkOperation) return true;

                                        if (Permissions[CNST_ALL][pObj][permission.Key][group] != null)
                                        {
                                            if (Permissions[CNST_ALL][pObj][permission.Key][group].Contains(pOperation)) return true;
                                        }
                                        //If the hashset of operation is null, we asume we don't filter by operation
                                        else
                                        {
                                            return true;
                                        }
                                    }
                                }

                                //Check if we have the all
                                if (permission.Value.ContainsKey(CNST_ALL))
                                {
                                    if (!checkOperation) return true;

                                    if (Permissions[CNST_ALL][pObj][permission.Key][CNST_ALL] != null)
                                    {
                                        if (Permissions[CNST_ALL][pObj][permission.Key][CNST_ALL].Contains(pOperation)) return true;
                                    }
                                    //If the hashset of operation is null, we asume we don't filter by operation
                                    else
                                    {
                                        return true;
                                    }
                                }
                            }
                        }

                    }
                }
            }

            return false;
        }


        /// <summary>
        /// Add Permission to a group for a product and object
        /// </summary>
        /// <param name="pProduct"></param>
        /// <param name="pObj"></param>
        /// <param name="pPermission"></param>
        /// <param name="pGroup"></param>
        /// <remarks></remarks>
        /// <returns>A boolean meaning if the group have permission</returns>
        public bool AddPermission(string pProduct, string pObj, string pPermission, string pGroup)
        {
            //--- Check if Permissions is not null ----------------
            if (Permissions == null)
                Permissions = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>>();

            //--- Check if we have the product -----------
            if (!Permissions.ContainsKey(pProduct))
                Permissions.Add(pProduct, new Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>());

            //--- Check if we have the object ------------
            if (!Permissions[pProduct].ContainsKey(pObj))
                Permissions[pProduct].Add(pObj, new Dictionary<string, Dictionary<string, HashSet<string>>>());

            //--- Check if we have the permission --------
            if (!Permissions[pProduct][pObj].ContainsKey(pPermission))
                Permissions[pProduct][pObj].Add(pPermission, new Dictionary<string, HashSet<string>>());

            //--- Check if we have the group -------------
            if (!Permissions[pProduct][pObj][pPermission].ContainsKey(pGroup))
                Permissions[pProduct][pObj][pPermission].Add(pGroup, null);

            return true;
        }

        /// <summary>
        /// Add Permission to execute an Operation for a group, product and object
        /// </summary>
        /// <param name="pProduct"></param>
        /// <param name="pObj"></param>
        /// <param name="pPermission"></param>
        /// <param name="pGroup"></param>
        /// <remarks></remarks>
        /// <returns>A boolean meaning if the group have permission</returns>
        public bool AddPermission(string pProduct, string pObj, string pPermission, string pGroup, string pOperation)
        {
            //Add StandardPermission
            AddPermission(pProduct, pObj, pPermission, pGroup);

            //Initialize hashset of operations if we dont have any, and add operation 
            if (Permissions[pProduct][pObj][pPermission][pGroup] == null)
            {
                Permissions[pProduct][pObj][pPermission][pGroup] = new HashSet<string>();
            }

            if (!Permissions[pProduct][pObj][pPermission][pGroup].Contains(pOperation))
            {
                Permissions[pProduct][pObj][pPermission][pGroup].Add(pOperation);
            }

            return true;
        }
    }
}
