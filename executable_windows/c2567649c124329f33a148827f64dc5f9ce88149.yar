rule HKTL_NET_GUID_Stealth_Kid_RAT
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii nocase wide
		$typelibguid1 = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
