rule HKTL_NET_GUID_Absinthe
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cameronhotchkies/Absinthe"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
