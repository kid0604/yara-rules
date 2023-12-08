rule HKTL_NET_NAME_C2Bridge
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/cobbr/C2Bridge"
		author = "Arnim Rupp"
		date = "2021-01-22"
		os = "windows"
		filetype = "executable"

	strings:
		$name = "C2Bridge" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
