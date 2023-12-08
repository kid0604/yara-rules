rule HKTL_NET_NAME_ADCollector
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		reference = "https://github.com/dev-2null/ADCollector"
		hash = "5391239f479c26e699b6f3a1d6a0a8aa1a0cf9a8"
		hash = "9dd0f322dd57b906da1e543c44e764954704abae"
		author = "Arnim Rupp"
		date = "2021-01-22"
		os = "windows"
		filetype = "executable"

	strings:
		$name = "ADCollector" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}
