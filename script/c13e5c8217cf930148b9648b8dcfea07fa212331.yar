rule HKTL_NET_GUID_MultiOS_ReverseShell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/belane/MultiOS_ReverseShell"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$typelibguid0 = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
