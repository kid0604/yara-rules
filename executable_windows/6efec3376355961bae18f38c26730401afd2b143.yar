rule HKTL_NET_GUID_Salsa_tools
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Hackplayers/Salsa-tools"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "276004bb-5200-4381-843c-934e4c385b66" ascii nocase wide
		$typelibguid1 = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
