rule HKTL_NET_GUID_PowerOPS
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fdiskyou/PowerOPS"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
