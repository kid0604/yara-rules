import "pe"

rule MSIL_Launcher_DUEDLLIGENCE_1
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'DUEDLLIGENCE' project."
		md5 = "a91bf61cc18705be2288a0f6f125068f"
		rev = 1
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "73948912-cebd-48ed-85e2-85fcd1d4f560" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
