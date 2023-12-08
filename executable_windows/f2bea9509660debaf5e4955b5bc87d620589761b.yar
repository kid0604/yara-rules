import "pe"

rule ProgramProtectorXPv10
{
	meta:
		author = "malware-lu"
		description = "Detects ProgramProtectorXPv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 58 83 D8 05 89 C3 81 C3 [4] 8B 43 64 50 }

	condition:
		$a0 at pe.entry_point
}
