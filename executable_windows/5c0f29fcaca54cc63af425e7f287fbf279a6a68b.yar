rule HKTL_NET_GUID_Obfuscator
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
