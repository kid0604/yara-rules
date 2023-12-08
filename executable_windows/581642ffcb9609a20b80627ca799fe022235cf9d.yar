import "pe"

rule PLINK8619841985
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FA 8C C7 8C D6 8B CC BA [2] 8E C2 26 }

	condition:
		$a0 at pe.entry_point
}
