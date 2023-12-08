rule HKTL_NET_GUID_Privilege_Escalation
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
