private rule is__Mirai_Satori_gen
{
	meta:
		description = "Detects Mirai Satori_gen"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
		date = "2018-01-05"
		os = "linux"
		filetype = "executable"

	strings:
		$st08 = "tftp -r satori" fullword nocase wide ascii
		$st09 = "/bins/satori" fullword nocase wide ascii
		$st10 = "satori" fullword nocase wide ascii
		$st11 = "SATORI" fullword nocase wide ascii

	condition:
		2 of them
}
