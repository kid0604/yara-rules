rule HKTL_NET_GUID_Mythic
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/its-a-feature/Mythic"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "91f7a9da-f045-4239-a1e9-487ffdd65986" ascii nocase wide
		$typelibguid1 = "0405205c-c2a0-4f9a-a221-48b5c70df3b6" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
