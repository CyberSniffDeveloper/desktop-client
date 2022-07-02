# CyberSniff
A network analysis tool similar to WireShark, but with less features, friendlier UI and geared towards the less networking savvy. The tool was actively sold for a one-time fee throughout 2018 to 2022 (4 years)

This is a build of CyberSniff with the authentication and all server communications and models stripped out so that it can be used after the server shutdown at Wednesday 1st June 2022. **This source code is partially redacted, all code to interface with the CyberSniff API has been removed**

This build was taken from the latest commit in the v3 branch of the private repository. This is an **official** build of the software and any others should be deemed **unofficial** and as such we do not provide any liability.

**Nor do we provide any liability for this repository either**

**For security purposes, the source code has been updated to use .NET 6 as it was previously using .NET 5, which is deprecated**

## Notice for support
Support will **not** be provided whatsoever for this product and no warranty is guaranteed for this product either. Issues relating to exceptions that are a code fault **may be fixed but we do not guarantee or warrant a fix being made and applied**.

As there is no server communication in this application (excluding IP-API), there is **no** updating solution, if a fix is released, it is entirely **your** ability to download and install the latest patch. The only time a patch will be developed and applied is when a security risk is posed, and even so it's unlikely that such will even be noticed in the first place.

## Getting started
To spin up this build on your machine, you need to head over to the Releases page and download the 'publish.zip' file and extract it on your machine to a seperate folder. **You will also need Npcap installed on your machine too**

Then you can simply run the 'CyberSniff.exe' file to start it up.

**The release build is NOT obfuscated in any way, you can decompile it and see every bit of the source code, granted that compile time stuff will be applied**

## Compilation
You **can** compile this source, although the actual source code for the v3 client is very poor as it was developed when the team was first starting out in C# software development. 

**You'll need the .NET 6 SDK**

Clone the repository and then run `dotnet publish -c Release` to compile the build. For a little intelligence check, we've added invalid code/configurations that you have to remove yourself to get it compiling correctly.
