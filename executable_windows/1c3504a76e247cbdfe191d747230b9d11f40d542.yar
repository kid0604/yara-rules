import "pe"

rule HKTL_NET_GUID_Adamantium_Thief_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/Adamantium-Thief"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii wide
		$typelibguid0up = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
