rule HKTL_NET_GUID_Nuages
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/p3nt4/Nuages"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
