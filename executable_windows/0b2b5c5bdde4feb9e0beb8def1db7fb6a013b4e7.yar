rule HKTL_NET_GUID_neo_ConfuserEx
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e98490bb-63e5-492d-b14e-304de928f81a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
