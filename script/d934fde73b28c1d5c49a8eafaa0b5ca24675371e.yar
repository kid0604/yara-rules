rule HKTL_NET_GUID_DotNetToJScript_LanguageModeBreakout
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout"
		author = "Arnim Rupp"
		date = "2021-01-21"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "deadb33f-fa94-41b5-813d-e72d8677a0cf" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
