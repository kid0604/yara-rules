import "pe"

rule HKTL_NET_GUID_Absinthe_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cameronhotchkies/Absinthe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii wide
		$typelibguid0up = "9936AE73-FB4E-4C5E-A5FB-F8AAEB3B9BD6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
