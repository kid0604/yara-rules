rule HKTL_NET_GUID_DecryptAutoLogon
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/securesean/DecryptAutoLogon"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "015a37fc-53d0-499b-bffe-ab88c5086040" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
