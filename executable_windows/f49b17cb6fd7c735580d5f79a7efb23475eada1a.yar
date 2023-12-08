import "pe"

rule RUAG_Cobra_Malware
{
	meta:
		description = "Detects a malware mentioned in the RUAG Case called Carbon/Cobra"
		author = "Florian Roth"
		reference = "https://goo.gl/N5MEj0"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Cobra\\Release\\Cobra.pdb" ascii

	condition:
		uint16(0)==0x5a4d and $s1
}
