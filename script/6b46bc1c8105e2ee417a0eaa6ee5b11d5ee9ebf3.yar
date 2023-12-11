rule HKTL_NET_GUID_PowerShdll
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/p3nt4/PowerShdll"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
