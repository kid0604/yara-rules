rule HKTL_NET_GUID_Snaffler
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SnaffCon/Snaffler"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii nocase wide
		$typelibguid1 = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
