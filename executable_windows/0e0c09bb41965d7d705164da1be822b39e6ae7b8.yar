rule HKTL_NET_GUID_SharpWifiGrabber
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/r3nhat/SharpWifiGrabber"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c0997698-2b73-4982-b25b-d0578d1323c2" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
