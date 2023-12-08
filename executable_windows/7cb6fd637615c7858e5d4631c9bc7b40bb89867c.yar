rule HKTL_NET_GUID_BadPotato
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BeichenDream/BadPotato"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0527a14f-1591-4d94-943e-d6d784a50549" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
