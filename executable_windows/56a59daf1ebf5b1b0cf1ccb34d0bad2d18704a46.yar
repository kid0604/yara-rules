import "pe"

rule PwDump_alt_1
{
	meta:
		description = "PwDump 6 variant"
		author = "Marc Stroebel"
		date = "2014-04-24"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
		$s6 = "Unable to query service status. Something is wrong, please manually check the st"
		$s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword

	condition:
		1 of them
}
