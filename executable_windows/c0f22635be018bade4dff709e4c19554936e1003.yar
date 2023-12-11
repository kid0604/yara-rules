rule HKTL_NET_GUID_AVIator
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Ch0pin/AVIator"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
