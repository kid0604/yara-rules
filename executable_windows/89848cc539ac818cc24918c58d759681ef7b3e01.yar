rule HKTL_NET_GUID_SharpTask
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpTask"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
