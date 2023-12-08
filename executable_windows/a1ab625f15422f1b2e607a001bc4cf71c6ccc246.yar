import "pe"

rule xtreme_rat : Trojan
{
	meta:
		author = "Kevin Falcoz"
		date = "23/02/2013"
		description = "Xtreme RAT"
		os = "windows"
		filetype = "executable"

	strings:
		$signature1 = {58 00 54 00 52 00 45 00 4D 00 45}

	condition:
		$signature1
}
