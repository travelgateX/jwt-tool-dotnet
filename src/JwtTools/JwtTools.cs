using System.Collections.Generic;
using System;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DotnetJwtTools
{    
    public class JwtTools
    {
        public bool isError = false;
        public string Error = null;
        private const string CNST_ALL = "all";
        private const string CNST_CRUD = "crud";
        private const string CNST_ADMIN = "a";
        private const string CNST_TEAM = "TEAM";
        private const string CNST_PRODUCT = "PRODUCT";

        //---------- BASIC PERMISSIONS -----------//
        private const string CNST_CREATE = "c";
        private const string CNST_UPDATE = "u";
        private const string CNST_DELETE = "d";
        private const string CNST_READ = "r";
        private const string CNST_EXECUTE = "x";

        // Product --> Object --> Permission --> Groups ... Api -> Operation -> read, Update -> Organizations..
        public Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>> Permissions { get; set; }
        public bool IsAdmin { get; set; }
        public HashSet<string> ExtraNode { get; set; }
        public HashSet<string> IamProducts { get; set; }

        public JwtTools(string pBearer, string pAdminGroup, string pJwtIamName, string pExtraValuePath = null)
        {
            this._NewPermissionTable(pBearer, pAdminGroup, pJwtIamName, pExtraValuePath);
        }

        public JwtTools(string pBearer, string pJwtIamName, string pExtraValuePath = null)
        {
            this._NewPermissionTable(pBearer, string.Empty, pJwtIamName, pExtraValuePath);
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
                //List<Claim> claims = _ValidateJwtToken(pBearer, config);
                string strJwt = _ExtractClaims(pBearer, pJwtIamName, pExtraValuePath);

                if (!string.IsNullOrEmpty(strJwt))
                {   
                    Jwt jwt = JsonConvert.DeserializeObject<Jwt>(strJwt);

                    this.IsAdmin = false;
                    this.Permissions = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>>();
                    this._BuildPermissions(new List<Jwt> { jwt }, new Dictionary<string, GroupTree>(), pAdminGroup);
                }
            }
            catch (Exception e)
            {
                this.Error = e.Message;
                this.isError = true;
                this.Permissions = null;
            }
        }


        #region JWT Validation
        //private static List<Claim> _ValidateJwtToken(string jwt, UserConfig config)
        //{
        //    var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(System.Text.Encoding.ASCII.GetBytes(config.ValidationPublicKey));
        //    TokenValidationParameters validationParameters =
        //        new TokenValidationParameters
        //        {
        //            ValidateIssuer = false,
        //            ValidateIssuerSigningKey = false,
        //            ValidateAudience = false,
        //            ValidateActor = false,
        //            ValidateLifetime = false,
        //            RequireExpirationTime = false,
        //            RequireSignedTokens = false
        //        };

        //    SecurityToken validatedToken;
        //    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

        //    ClaimsPrincipal ret = handler.ValidateToken(jwt.Split(' ').Last(), validationParameters, out validatedToken);

        //    if (ret != null && ret.Identities.Count() > 0 && ret.Identities.First().IsAuthenticated && ret.Identities.First().Claims.Count() > 0)
        //    {
        //        return (List<Claim>)ret.Identities.First().Claims;
        //    }
        //    else
        //    {
        //        return null;
        //    }
        //} 
        #endregion

        //Return the IAM and extravalue claims value
        private string _ExtractClaims(string pJwt, string pJwtIamName, string pExtraValuePath)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = (JwtSecurityToken)handler.ReadJwtToken(pJwt);

            bool getExtraValue = !string.IsNullOrEmpty(pExtraValuePath);
            
            string ret = string.Empty;

            foreach (Claim claim in token.Claims)
            {
                if (claim.Type == pJwtIamName) ret = claim.Value;
                if (getExtraValue && claim.Type == pExtraValuePath)
                {
                    if (this.ExtraNode == null) ExtraNode = new HashSet<string>();
                    if (!this.ExtraNode.Contains(claim.Value))
                        this.ExtraNode.Add(claim.Value);
                }
            }

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
                    if (this.IamProducts == null) this.IamProducts = new HashSet<string>();
                    if (!this.IamProducts.Contains(group.GroupCode)) this.IamProducts.Add(group.GroupCode);
                }

                //Fill the tree with the data on the group
                pTree[group.GroupCode] = new GroupTree { Groups = new Dictionary<string, GroupTree>(), GroupType = group.Type };

                //Check the Products
                //if (group.GroupAdditional?.Count > 0) this._ExtractAdditionalGroups(group.GroupAdditional);

                bool isAdmin = _FillPermissionsFromProducts(group.GroupPermissions, this.Permissions, group.GroupCode, pAdminGroup, group.Type);
                //if (isAdmin) this.IsAdmin = true;

                //Call recursivity
                Dictionary<string, GroupTree> groupTree = pTree[group.GroupCode].Groups;
                this._BuildPermissions(group.GroupDescendants, groupTree, pAdminGroup);
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
                            if (this.IamProducts == null) this.IamProducts = new HashSet<string>();
                            if (!this.IamProducts.Contains(CNST_ALL)) this.IamProducts.Add(CNST_ALL);
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

        private void _ExtractAdditionalGroups(Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>> pGroupAdditional)
        {
            if (this.Permissions == null) this.Permissions = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>>();
            string perm = string.Empty;
            //for each product
            foreach (var groupProd in pGroupAdditional)
            {
                if (!this.Permissions.ContainsKey(groupProd.Key))
                    this.Permissions.Add(groupProd.Key, new Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>());

                //for each api
                foreach (var groupApi in groupProd.Value)
                {
                    if (!this.Permissions[groupProd.Key].ContainsKey(groupApi.Key))
                        this.Permissions[groupProd.Key].Add(groupApi.Key, new Dictionary<string, Dictionary<string, HashSet<string>>>());

                    //for each object
                    foreach (var groupObj in groupApi.Value)
                    {
                        //if (!this.Permissions[groupProd.Key][groupApi.Key].ContainsKey(groupObj.Key))
                        //    this.Permissions[groupProd.Key][groupApi.Key].Add(groupObj.Key, new Dictionary<string, HashSet<string>>());

                        //foreach permission
                        foreach (var groupPer in groupObj.Value)
                        {
                            perm = groupPer;
                            if (perm == "1a") perm = CNST_ADMIN;

                            //add Permission
                            if (!this.Permissions[groupProd.Key][groupApi.Key].ContainsKey(perm))
                                this.Permissions[groupProd.Key][groupApi.Key].Add(perm, new Dictionary<string, HashSet<string>>());

                            if (!this.Permissions[groupProd.Key][groupApi.Key][perm].ContainsKey(groupObj.Key))
                                this.Permissions[groupProd.Key][groupApi.Key][perm].Add(groupObj.Key, null);
                        }
                    }
                }
               
            }
        }

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
            return this.CheckPermission(pProduct, pObj, pPermission, new List<string> { pGroup }, pOperation);
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
            if (this.IsAdmin) { return true; }
            if (this.Permissions == null) return false;
            bool checkOperation = !string.IsNullOrEmpty(pOperation);
            //---

            //Check for concrete product
            if (this.Permissions.ContainsKey(pProduct))
            {
                //Check for all object
                if (this.Permissions[pProduct].ContainsKey(CNST_ALL))
                {
                    if (this.Permissions[pProduct][CNST_ALL].ContainsKey(pPermission))
                    {
                        foreach (string group in pGroups)
                        {
                            //Check if have the group
                            if (this.Permissions[pProduct][CNST_ALL][pPermission].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                //Check if we have the operationAdded to operations list
                                if (this.Permissions[pProduct][CNST_ALL][pPermission][group] != null)
                                {
                                    if (this.Permissions[pProduct][CNST_ALL][pPermission][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        //Check if we have all the groups
                        if (this.Permissions[pProduct][CNST_ALL][pPermission].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            //Check if we have the operationAdded to operations list
                            if (this.Permissions[pProduct][CNST_ALL][pPermission][CNST_ALL] != null)
                            {
                                if (this.Permissions[pProduct][CNST_ALL][pPermission][CNST_ALL].Contains(pOperation)) return true;
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
                    foreach (var permission in this.Permissions[pProduct][CNST_ALL])
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
                                    if (this.Permissions[pProduct][CNST_ALL][permission.Key][group] != null)
                                    {
                                        if (this.Permissions[pProduct][CNST_ALL][permission.Key][group].Contains(pOperation)) return true;
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
                                if (this.Permissions[pProduct][CNST_ALL][permission.Key][CNST_ALL] != null)
                                {
                                    if (this.Permissions[pProduct][CNST_ALL][permission.Key][CNST_ALL].Contains(pOperation)) return true;
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
                if (this.Permissions[pProduct].ContainsKey(pObj))
                {                    
                    if (this.Permissions[pProduct][pObj].ContainsKey(pPermission))
                    {
                        foreach (string group in pGroups)
                        {
                            if (this.Permissions[pProduct][pObj][pPermission].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (this.Permissions[pProduct][pObj][pPermission][group] != null)
                                {
                                    if (this.Permissions[pProduct][pObj][pPermission][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }

                            }
                        }

                        if (this.Permissions[pProduct][pObj][pPermission].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (this.Permissions[pProduct][pObj][pPermission][CNST_ALL] != null)                                
                            {
                                if (this.Permissions[pProduct][pObj][pPermission][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }

                    }
                    else if (this.Permissions[pProduct][pObj].ContainsKey(CNST_CRUD))
                    {
                        foreach (string group in pGroups)
                        {
                            if (this.Permissions[pProduct][pObj][CNST_CRUD].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (this.Permissions[pProduct][pObj][CNST_CRUD][group] != null)
                                {
                                    if (this.Permissions[pProduct][pObj][CNST_CRUD][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        if (this.Permissions[pProduct][pObj][CNST_CRUD].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (this.Permissions[pProduct][pObj][CNST_CRUD][CNST_ALL] != null)
                            {
                                if (this.Permissions[pProduct][pObj][CNST_CRUD][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }
                    }
                    else if (this.Permissions[pProduct][pObj].ContainsKey(CNST_ADMIN))
                    {
                        foreach (string group in pGroups)
                        {
                            if (this.Permissions[pProduct][pObj][CNST_ADMIN].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (this.Permissions[pProduct][pObj][CNST_ADMIN][group] != null)
                                {
                                    if (this.Permissions[pProduct][pObj][CNST_ADMIN][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        if (this.Permissions[pProduct][pObj][CNST_ADMIN].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (this.Permissions[pProduct][pObj][CNST_ADMIN][CNST_ALL] != null)
                            {
                                if (this.Permissions[pProduct][pObj][CNST_ADMIN][CNST_ALL].Contains(pOperation)) return true;
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
            if (this.Permissions.ContainsKey(CNST_ALL))
            {
                //Check for all object
                if (this.Permissions[CNST_ALL].ContainsKey(CNST_ALL))
                {
                    //Check for all permission
                    if (this.Permissions[CNST_ALL][CNST_ALL].ContainsKey(pPermission))
                    {
                        foreach (string group in pGroups)
                        {
                            //Check if have the group
                            if (this.Permissions[CNST_ALL][CNST_ALL][pPermission].ContainsKey(group))
                            {
                                if (!checkOperation) return true;

                                if (this.Permissions[CNST_ALL][CNST_ALL][pPermission][group] != null)
                                {
                                    if (this.Permissions[CNST_ALL][CNST_ALL][pPermission][group].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }

                        //Check if have the all
                        if (this.Permissions[CNST_ALL][CNST_ALL][pPermission].ContainsKey(CNST_ALL))
                        {
                            if (!checkOperation) return true;

                            if (this.Permissions[CNST_ALL][CNST_ALL][pPermission][CNST_ALL] != null)
                            {
                                 if (this.Permissions[CNST_ALL][CNST_ALL][pPermission][CNST_ALL].Contains(pOperation)) return true;
                            }
                            //If the hashset of operation is null, we asume we don't filter by operation
                            else
                            {
                                return true;
                            }
                        }
                    }
                   
                    //Check if we have major permission
                    foreach (var permission in this.Permissions[CNST_ALL][CNST_ALL])
                    {                            
                        if (permission.Key.StartsWith(CNST_CRUD) || permission.Key.Equals(CNST_ADMIN))
                        {
                            foreach (string group in pGroups)
                            {
                                //Check if we have the group
                                if (permission.Value.ContainsKey(group))
                                {
                                    if (!checkOperation) return true;

                                    if (this.Permissions[CNST_ALL][CNST_ALL][permission.Key][group] != null)
                                    {
                                        if (this.Permissions[CNST_ALL][CNST_ALL][permission.Key][group].Contains(pOperation)) return true;
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

                                if (this.Permissions[CNST_ALL][CNST_ALL][permission.Key][CNST_ALL] != null)
                                {
                                    if (this.Permissions[CNST_ALL][CNST_ALL][permission.Key][CNST_ALL].Contains(pOperation)) return true;
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
                    if (this.Permissions[CNST_ALL].ContainsKey(pObj))
                    {
                        if (this.Permissions[CNST_ALL][pObj].ContainsKey(pPermission))
                        {
                            foreach (string group in pGroups)
                            {
                                //Check if we have the group
                                if (this.Permissions[CNST_ALL][pObj][pPermission].ContainsKey(group))
                                {
                                    if (!checkOperation) return true;

                                    if (this.Permissions[CNST_ALL][pObj][pPermission][group] != null)
                                    {
                                        if (this.Permissions[CNST_ALL][pObj][pPermission][group].Contains(pOperation)) return true;
                                    }
                                    //If the hashset of operation is null, we asume we don't filter by operation
                                    else
                                    {
                                        return true;
                                    }
                                }
                            }

                            //Check if we have the all
                            if (this.Permissions[CNST_ALL][pObj][pPermission].ContainsKey(CNST_ALL))
                            {
                                if (!checkOperation) return true;

                                if (this.Permissions[CNST_ALL][pObj][pPermission][CNST_ALL] != null)
                                {
                                    if (this.Permissions[CNST_ALL][pObj][pPermission][CNST_ALL].Contains(pOperation)) return true;
                                }
                                //If the hashset of operation is null, we asume we don't filter by operation
                                else
                                {
                                    return true;
                                }
                            }
                        }
                      
                        //Check if we have major permission
                        foreach (var permission in this.Permissions[CNST_ALL][pObj])
                        {
                            if (permission.Key.StartsWith(CNST_CRUD) || permission.Key.Equals(CNST_ADMIN))
                            {
                                foreach (string group in pGroups)
                                {
                                    //Check if we have the group
                                    if (permission.Value.ContainsKey(group))
                                    {
                                        if (!checkOperation) return true;

                                        if (this.Permissions[CNST_ALL][pObj][permission.Key][group] != null)
                                        {
                                            if (this.Permissions[CNST_ALL][pObj][permission.Key][group].Contains(pOperation)) return true;
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

                                    if (this.Permissions[CNST_ALL][pObj][permission.Key][CNST_ALL] != null)
                                    {
                                        if (this.Permissions[CNST_ALL][pObj][permission.Key][CNST_ALL].Contains(pOperation)) return true;
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
            if (this.Permissions == null)
                this.Permissions = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>>();

            //--- Check if we have the product -----------
            if (!this.Permissions.ContainsKey(pProduct))
                this.Permissions.Add(pProduct, new Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>>());

            //--- Check if we have the object ------------
            if (!this.Permissions[pProduct].ContainsKey(pObj))
                this.Permissions[pProduct].Add(pObj, new Dictionary<string, Dictionary<string, HashSet<string>>>());

            //--- Check if we have the permission --------
            if (!this.Permissions[pProduct][pObj].ContainsKey(pPermission))
                this.Permissions[pProduct][pObj].Add(pPermission, new Dictionary<string, HashSet<string>>());

            //--- Check if we have the group -------------
            if (!this.Permissions[pProduct][pObj][pPermission].ContainsKey(pGroup))
                this.Permissions[pProduct][pObj][pPermission].Add(pGroup, null);

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
            this.AddPermission(pProduct, pObj, pPermission, pGroup);
            
            //Initialize hashset of operations if we dont have any, and add operation 
            if (this.Permissions[pProduct][pObj][pPermission][pGroup] == null)
            {
                this.Permissions[pProduct][pObj][pPermission][pGroup] = new HashSet<string>();
            }

            if (!this.Permissions[pProduct][pObj][pPermission][pGroup].Contains(pOperation))
            {
                this.Permissions[pProduct][pObj][pPermission][pGroup].Add(pOperation);
            }

            return true;
        }
    }
}
