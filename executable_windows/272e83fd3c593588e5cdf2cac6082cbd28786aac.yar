rule HKTL_NET_GUID_Evasor
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cyberark/Evasor"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
