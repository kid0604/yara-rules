import "pe"

rule mew_11_xx : Packer
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/03/2013"
		description = "MEW 11"
		os = "windows"
		filetype = "executable"

	strings:
		$signature1 = {50 72 6F 63 41 64 64 72 65 73 73 00 E9 [6-7] 00 00 00 00 00 00 00 00 00 [7] 00}
		$signature2 = "MEW"

	condition:
		$signature1 and $signature2
}
