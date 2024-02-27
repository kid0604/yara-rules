import "pe"

rule HKTL_NET_GUID_SharpTokenFinder
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/HuskyHacks/SharpTokenFinder"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2023-12-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "572804d3-dbd6-450a-be64-2e3cb54fd173" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
