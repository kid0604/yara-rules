rule HKTL_NET_GUID_ADFSDump
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fireeye/ADFSDump"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "9ee27d63-6ac9-4037-860b-44e91bae7f0d" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
