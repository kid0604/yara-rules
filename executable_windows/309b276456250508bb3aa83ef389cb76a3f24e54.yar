rule HKTL_NET_GUID_SharpCookieMonster
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/m0rv4i/SharpCookieMonster"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
