rule HKTL_NET_GUID_wsManager
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/guillaC/wsManager"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9480809e-5472-44f3-b076-dcdf7379e766" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
