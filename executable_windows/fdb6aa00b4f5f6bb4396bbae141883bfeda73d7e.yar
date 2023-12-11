rule HKTL_NET_GUID_Keylogger
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BlackVikingPro/Keylogger"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
