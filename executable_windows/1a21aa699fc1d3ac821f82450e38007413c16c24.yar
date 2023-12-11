rule HKTL_NET_GUID_AntiDebug
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/AntiDebug"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "997265c1-1342-4d44-aded-67964a32f859" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
