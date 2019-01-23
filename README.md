# jwt-tool-dotnet
.NET Core 1 JWT Tool 

https://github.com/dotnet/designs/issues/2

# How to use the Tool

To use the tool, you'll need some data:
- The auth0 Bearer. 
- The Url of the IAM

The first step is to import the Nuget in your project.

Now we create the **JwtTools** object.
**JwtTools** jwtTools = new **JwtTools**(bearer, "Iam path, in example https://travelgatex.com/iam");

And now, you can use the Tool.

**Check Permissions**

jwtTools.CheckPermission("Api", "Product", "Permission", "Orgenization");
bool ok = jwtTools.CheckPermission("iam", "grp", "r", "xtg");

**Add permissions:**

jwt.AddPermission("iam", "grp", "r", "tgx");

**Add Operations to an existing permission** (or create a new one with this operation).

jwt.AddPermission("iam", "grp", "r", "tgx", "ReadCommission");

**Check the permission with the operation:**

bool ok = jwtTools.CheckPermission("iam", "grp", "r", "tgx", "ReadCommission");
