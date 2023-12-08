rule HKTL_NET_GUID_rat_shell
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/stphivos/rat-shell"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii nocase wide
		$typelibguid1 = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
