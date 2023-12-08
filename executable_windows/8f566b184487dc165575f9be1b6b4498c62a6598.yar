rule HKTL_NET_NAME_AmsiBypass
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/0xB455/AmsiBypass"
		hash = "8fa4ba512b34a898c4564a8eac254b6a786d195b"
		author = "Arnim Rupp"
		date = "2021-01-22"
		os = "windows"
		filetype = "executable"

	strings:
		$name = "AmsiBypass" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
