import "pe"

rule APT_APT41_CN_ELF_Speculoos_Backdoor
{
	meta:
		description = "Detects Speculoos Backdoor used by APT41"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/"
		date = "2020-04-14"
		score = 90
		hash1 = "6943fbb194317d344ca9911b7abb11b684d3dca4c29adcbcff39291822902167"
		hash2 = "99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28"
		os = "linux"
		filetype = "executable"

	strings:
		$xc1 = { 2F 70 72 69 76 61 74 65 2F 76 61 72 00 68 77 2E
               70 68 79 73 6D 65 6D 00 68 77 2E 75 73 65 72 6D
               65 6D 00 4E 41 2D 4E 41 2D 4E 41 2D 4E 41 2D 4E
               41 2D 4E 41 00 6C 6F 30 00 00 00 00 25 30 32 78
               2D 25 30 32 78 2D 25 30 32 78 2D 25 30 32 78 2D
               25 30 32 78 2D 25 30 32 78 0A 00 72 00 4E 41 00
               75 6E 61 6D 65 20 2D 76 }
		$s1 = "badshell" ascii fullword
		$s2 = "hw.physmem" ascii fullword
		$s3 = "uname -v" ascii fullword
		$s4 = "uname -s" ascii fullword
		$s5 = "machdep.tsc_freq" ascii fullword
		$s6 = "/usr/sbin/config.bak" ascii fullword
		$s7 = "enter MessageLoop..." ascii fullword
		$s8 = "exit StartCBProcess..." ascii fullword
		$sc1 = { 72 6D 20 2D 72 66 20 22 25 73 22 00 2F 70 72 6F
               63 2F }

	condition:
		uint16(0)==0x457f and filesize <600KB and 1 of ($x*) or 4 of them
}
