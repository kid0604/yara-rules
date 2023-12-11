import "pe"

rule EQGRP_false_alt_1
{
	meta:
		description = "Detects tool from EQGRP toolset - file false.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
			2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
			0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
			0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
			00 25 64 20 2D 20 25 64 }

	condition:
		uint16(0)==0x5a4d and filesize <50KB and $s1
}
