import "pe"

rule Shamoon2_ComComp
{
	meta:
		description = "Detects Shamoon 2.0 Communication Components"
		author = "Florian Roth (with Binar.ly)"
		reference = "https://goo.gl/jKIfGB"
		date = "2016-12-01"
		score = 70
		hash1 = "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mkdir %s%s > nul 2>&1" fullword ascii
		$s2 = "p[%s%s%d.%s" fullword ascii
		$op1 = { 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 }
		$op2 = { c8 02 d2 c0 e9 06 02 d2 24 3f 02 d1 88 45 fb 8d }
		$op3 = { 0c 3b 40 8d 4e 01 47 3b c1 7c d8 83 fe 03 7d 1c }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and ( all of ($s*) or all of ($op*))
}
