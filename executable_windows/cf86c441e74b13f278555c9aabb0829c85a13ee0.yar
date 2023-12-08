import "pe"

rule EquationDrug_HDDSSD_Op
{
	meta:
		description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "nls_933w.dll" fullword ascii

	condition:
		all of them
}
