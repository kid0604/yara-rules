import "pe"

rule VxCompiler
{
	meta:
		author = "malware-lu"
		description = "Detects VxCompiler malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }

	condition:
		$a0 at pe.entry_point
}
