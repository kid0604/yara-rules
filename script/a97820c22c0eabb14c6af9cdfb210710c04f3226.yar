import "pe"

rule adfind_14335
{
	meta:
		description = "Find.bat using AdFind"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
		date = "2022-09-12"
		hash1 = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "joeware.net" nocase wide ascii
		$s1 = "xx.cpp" nocase wide ascii
		$s2 = "xxtype.cpp" nocase wide ascii
		$s3 = "Joe Richards" nocase wide ascii
		$s4 = "RFC 2253" nocase wide ascii
		$s5 = "RFC 2254" nocase wide ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of ($x*) or 4 of ($s*)
}
