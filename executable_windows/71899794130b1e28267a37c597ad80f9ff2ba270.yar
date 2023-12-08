import "pe"

rule lost_door : Trojan
{
	meta:
		author = "Kevin Falcoz"
		date = "23/02/2013"
		description = "Lost Door"
		os = "windows"
		filetype = "executable"

	strings:
		$signature1 = {45 44 49 54 5F 53 45 52 56 45 52}

	condition:
		$signature1
}
