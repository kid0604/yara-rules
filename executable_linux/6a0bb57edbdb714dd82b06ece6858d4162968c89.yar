rule MAL_EXPL_Perfctl_Oct24
{
	meta:
		description = "Detects exploits used in relation with Perfctl malware campaigns"
		author = "Florian Roth"
		reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
		date = "2024-10-09"
		score = 80
		hash1 = "22e4a57ac560ebe1eff8957906589f4dd5934ee555ebcc0f7ba613b07fad2c13"
		id = "1f525eaf-445c-592e-bfa4-e9846390dd1d"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "Exploit failed. Target is most likely patched." ascii fullword
		$s2 = "SHELL=pkexec" ascii fullword
		$s3 = "/dump_" ascii fullword
		$s4 = ".EYE$" ascii

	condition:
		uint16(0)==0x457f and filesize <30000KB and 2 of them or all of them
}
