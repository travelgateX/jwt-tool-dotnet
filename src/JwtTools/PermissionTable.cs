using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace dotnet_jwt_tools
{
    // --------------------- DATA STRUCTURE DEFINITION --------------------- //
    #region data structure

    [JsonObject]
    public struct Jwt
    {
        //Group Code
        public string c { get; set; }
        //Group Descendants
        public List<Jwt> g { get; set; }
        //Group Type
        public string t { get; set; }
        //Group Permissions
        public Dictionary<string, Dictionary<string, List<string>>> p { get; set; }
        //Group Additional
        public object a { get; set; }
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
    public struct GroupTree
    {
        public string GroupType { get; set; }
        public Dictionary<string, GroupTree> Groups { get; set; }
    }

    public struct _Permissions
    {
        public bool Update { get; set; }
        public bool Create { get; set; }
        public bool Delete { get; set; }
        public bool Read { get; set; }
        public bool Enabled { get; set; }
        public string OtherPermissions { get; set; }

        public _Permissions(bool status)
        {
            Update = status;
            Create = status;
            Delete = status;
            Read = status;
            Enabled = status;
            OtherPermissions = string.Empty;
        }
    }

    #endregion
}
