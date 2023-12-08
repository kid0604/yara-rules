rule HKTL_NET_GUID_XORedReflectiveDLL
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/XORedReflectiveDLL"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii nocase wide
		$typelibguid1 = "30eef7d6-cee8-490b-829f-082041bc3141" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
