import "pe"

rule DBPEvxxxDingBoy
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of DBPEvxxxDingBoy malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 20 [2] 40 [29] 9C 55 57 56 52 51 53 9C E8 [4] 5D 81 ED }

	condition:
		$a0 at pe.entry_point
}
