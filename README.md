# jwt-tool-dotnet
.NET Core 1 JWT Tool 

https://github.com/dotnet/designs/issues/2

# How to use the Tool

To use the tool, you'll need some data:
- The IAM Bearer. 
- The Url of the Auth0 of your company.
- The PublicKey of the Auth0 of your company.
- The base Url of the claims.
- The Uri of the IAM and MemberID Url.
- Name of the Admin Group.

The first step is to import the Nuget in your project.

After that you have to create a UserConfig Object.

**UserConfig** userConfig = new **UserConfig**("Auth0 Url", 
                "Auth0 Public Key", 
                "Claim Base URl i.e. https://xmltravelgate.com/", 
                "IAM URI i.e. iam",
                "MemberID URI i.e. member_id");

The Next step is to Initialize the tool with the Bearer, the Admin Group and the UserConfig: 
**JwtTools** jwtTools = new **JwtTools**(bearer, string.Empty, userConfig);

And now, you can use the Tool!

**bool** ok = jwtTools.CheckPermission("iam", "grp", "r", "xtg");
