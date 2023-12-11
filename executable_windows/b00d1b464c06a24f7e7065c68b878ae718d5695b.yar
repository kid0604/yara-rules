rule HKTL_NET_GUID_SharpShot
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tothi/SharpShot"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
