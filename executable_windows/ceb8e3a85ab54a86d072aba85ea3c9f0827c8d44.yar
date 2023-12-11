rule HKTL_NET_GUID_TeleShadow2
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ParsingTeam/TeleShadow2"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "42c5c356-39cf-4c07-96df-ebb0ccf78ca4" ascii nocase wide
		$typelibguid1 = "0242b5b1-4d26-413e-8c8c-13b4ed30d510" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
