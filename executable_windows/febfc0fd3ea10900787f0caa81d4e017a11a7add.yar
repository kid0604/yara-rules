import "pe"

rule Install_Shield_2000
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 5.0"
		group = "15"
		function = "16"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 }

	condition:
		$a0 at pe.entry_point
}
