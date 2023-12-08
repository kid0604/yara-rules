rule HKTL_NET_GUID_SharpSniper
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/HunnicCyber/SharpSniper"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
