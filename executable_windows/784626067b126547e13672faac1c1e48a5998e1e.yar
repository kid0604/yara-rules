rule HKTL_NET_GUID_BackNet
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/valsov/BackNet"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9fdae122-cd1e-467d-a6fa-a98c26e76348" ascii nocase wide
		$typelibguid1 = "243c279e-33a6-46a1-beab-2864cc7a499f" ascii nocase wide
		$typelibguid2 = "a7301384-7354-47fd-a4c5-65b74e0bbb46" ascii nocase wide
		$typelibguid3 = "982dc5b6-1123-428a-83dd-d212490c859f" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
