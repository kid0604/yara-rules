rule HKTL_NET_GUID_SharpHound3
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/BloodHoundAD/SharpHound3"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "a517a8de-5834-411d-abda-2d0e1766539c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
