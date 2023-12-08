rule HKTL_NET_GUID_SharpGPOAbuse
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/SharpGPOAbuse"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4f495784-b443-4838-9fa6-9149293af785" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
