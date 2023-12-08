rule HKTL_NET_GUID_Internal_Monologue
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/eladshamir/Internal-Monologue"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii nocase wide
		$typelibguid1 = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
