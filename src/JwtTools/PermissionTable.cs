using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace dotnet_jwt_tools
{
    // --------------------- DATA STRUCTURE DEFINITION --------------------- //
    #region data structure

    [JsonObject]
    public class Jwt
    {
        [JsonProperty(PropertyName = "c")]
        public string GroupCode { get; set; }
        [JsonProperty(PropertyName = "g")]
        public List<Jwt> GroupDescendants { get; set; }
        [JsonProperty(PropertyName = "t")]
        public string Type { get; set; }
        [JsonProperty(PropertyName = "p")]
        public Dictionary<string, Dictionary<string, List<string>>> GroupPermissions { get; set; }
        [JsonProperty(PropertyName = "a")]
        public object GroupAdditional { get; set; }
    }


    [JsonObject]
    public class PermissionTable
    {
        // Product --> Object --> Permission --> Groups ... Api -> Operation -> read, Update -> Organizations..
        public Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, string>>>> Permissions { get; set; }
        public bool IsAdmin { get; set; }
        public string Bearer { get; set; }
        public Dictionary<string, GroupTree> Groups { get; set; }
        public string MemberId { get; set; }
    }

    [JsonObject]
    public class GroupTree
    {
        public string GroupType { get; set; }
        public Dictionary<string, GroupTree> Groups { get; set; }
    }

    //public struct _Permissions
    //{
    //    public bool Update { get; set; }
    //    public bool Create { get; set; }
    //    public bool Delete { get; set; }
    //    public bool Read { get; set; }
    //    public bool Enabled { get; set; }
    //    public string OtherPermissions { get; set; }

    //    public _Permissions(bool status)
    //    {
    //        Update = status;
    //        Create = status;
    //        Delete = status;
    //        Read = status;
    //        Enabled = status;
    //        OtherPermissions = string.Empty;
    //    }
    //}

    #endregion
}
