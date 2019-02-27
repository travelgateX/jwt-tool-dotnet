using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace DotnetJwtTools
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
        public Dictionary<string, Dictionary<string, Dictionary<string, HashSet<string>>>> GroupAdditional { get; set; }
    }

    [JsonObject]
    public class GroupTree
    {
        public string GroupType { get; set; }
        public Dictionary<string, GroupTree> Groups { get; set; }
    }

    #endregion
}
