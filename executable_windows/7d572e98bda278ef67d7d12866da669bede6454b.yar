rule HKTL_NET_GUID_UAC_SilentClean
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/EncodeGroup/UAC-SilentClean"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "948152a4-a4a1-4260-a224-204255bfee72" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
