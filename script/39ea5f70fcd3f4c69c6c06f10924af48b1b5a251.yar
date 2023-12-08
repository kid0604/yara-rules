rule HKTL_NET_GUID_AmsiScanBufferBypass
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
