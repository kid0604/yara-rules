import "pe"

rule Loader_MSIL_InMemoryCompilation_1
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'In-MemoryCompilation' project."
		md5 = "dd8805d0e470e59b829d98397507d8c2"
		rev = 2
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "524d2687-0042-4f93-b695-5579f3865205" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
