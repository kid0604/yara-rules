rule HKTL_NET_GUID_SharpLocker
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Pickfordmatt/SharpLocker"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
