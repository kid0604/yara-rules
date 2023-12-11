rule HKTL_NET_GUID_SharpSocks
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/nettitude/SharpSocks"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii nocase wide
		$typelibguid1 = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
