rule ROKRAT_loader : TAU DPRK APT
{
	meta:
		author = "CarbonBlack Threat Research"
		date = "2018-Jan-11"
		description = "Designed to catch loader observed used with ROKRAT malware"
		reference = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"
		rule_version = 1
		yara_version = "3.7.0"
		TLP = "White"
		exemplar_hashes = "e1546323dc746ed2f7a5c973dcecc79b014b68bdd8a6230239283b4f775f4bbd"
		os = "windows"
		filetype = "executable"

	strings:
		$n1 = "wscript.exe"
		$n2 = "cmd.exe"
		$s1 = "CreateProcess"
		$s2 = "VirtualAlloc"
		$s3 = "WriteProcessMemory"
		$s4 = "CreateRemoteThread"
		$s5 = "LoadResource"
		$s6 = "FindResource"
		$b1 = {33 C9 33 C0 E8 00 00 00 00 5E}
		$b2 = /\xB9.{3}\x00\x81\xE9?.{3}\x00/
		$b3 = {03 F1 83 C6 02}
		$b4 = {3E 8A 06 34 90 46}
		$b5 = {3E 30 06 46 49 83 F9 00 75 F6}
		$hpt_1 = {68 EC 97 03 0C}
		$hpt_2 = {68 54 CA AF 91}
		$hpt_3 = {68 8E 4E 0E EC}
		$hpt_4 = {68 AA FC 0D 7C}
		$hpt_5 = {68 1B C6 46 79}
		$hpt_6 = {68 F6 22 B9 7C}
		$henc_1 = {7B FF 84 10 1F}
		$henc_2 = {7B 47 D9 BC 82}
		$henc_3 = {7B 9D 5D 1D EC}
		$henc_4 = {7B B9 EF 1E 6F}
		$henc_5 = {7B 08 D5 55 6A}
		$henc_6 = {7B E5 31 AA 6F}

	condition:
		(1 of ($n*) and 4 of ($s*) and 4 of ($b*)) or all of ($hpt*) or all of ($henc*)
}
