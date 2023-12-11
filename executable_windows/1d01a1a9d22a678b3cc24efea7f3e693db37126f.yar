import "pe"

rule HackTool_MSIL_SharPivot_4
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the SharPivot project."
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		rev = 3
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid1 = "44B83A69-349F-4A3E-8328-A45132A70D62" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}
