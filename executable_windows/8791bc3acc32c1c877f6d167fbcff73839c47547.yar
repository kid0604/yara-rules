rule HKTL_NET_GUID_Naga
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/byt3bl33d3r/Naga"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "99428732-4979-47b6-a323-0bb7d6d07c95" ascii nocase wide
		$typelibguid1 = "a2c9488f-6067-4b17-8c6f-2d464e65c535" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
