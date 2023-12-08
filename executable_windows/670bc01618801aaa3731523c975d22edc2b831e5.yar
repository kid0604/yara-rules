rule HKTL_NET_GUID_Adamantium_Thief
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/LimerBoy/Adamantium-Thief"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
