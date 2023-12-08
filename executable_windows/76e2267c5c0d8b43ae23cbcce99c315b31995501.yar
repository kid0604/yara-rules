rule HKTL_NET_NAME_reconness
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/reconness/reconness"
		author = "Arnim Rupp"
		date = "2021-01-22"
		os = "windows"
		filetype = "executable"

	strings:
		$name = "reconness" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
