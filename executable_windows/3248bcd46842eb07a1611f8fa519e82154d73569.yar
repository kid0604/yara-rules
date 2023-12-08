import "pe"

rule apt_equation_keyword
{
	meta:
		description = "Rule to detect Equation group's keyword in executable file"
		author = "Florian Roth @4nc4p"
		last_modified = "2015-09-26"
		reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Backsnarf_AB25" wide
		$a2 = "Backsnarf_AB25" ascii

	condition:
		uint16(0)==0x5a4d and 1 of ($a*)
}
