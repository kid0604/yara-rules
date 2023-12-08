rule HKTL_NET_GUID_BypassUAC
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cnsimo/BypassUAC"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii nocase wide
		$typelibguid1 = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
