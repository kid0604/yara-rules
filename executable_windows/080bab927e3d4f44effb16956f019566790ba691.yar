import "pe"

rule APT_HackTool_MSIL_SHARPSACK_1
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsack' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		rev = 2
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "1946808a-1a01-40c5-947b-8b4c3377f742" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
