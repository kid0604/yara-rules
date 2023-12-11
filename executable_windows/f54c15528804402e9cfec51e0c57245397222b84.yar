import "pe"

rule IMPLANT_4_v9
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$a = "wevtutil clear-log" ascii wide nocase
		$b = "vssadmin delete shadows" ascii wide nocase
		$c = "AGlobal\\23d1a259-88fa-41df-935f-cae523bab8e6" ascii wide nocase
		$d = "Global\\07fd3ab3-0724-4cfd-8cc2-60c0e450bb9a" ascii wide nocase
		$openPhysicalDiskOverwriteWithZeros = { 57 55 33 C9 51 8B C3 99 57 52
         50 E8 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 83 C4 10 84 C0 75 21 33 C0 89
         44 24 10 89 44 24 14 6A 01 8B C7 99 8D 4C 24 14 51 52 50 56 FF 15 ??
         ?? ?? ?? 85 C0 74 0B 83 C3 01 81 FB 00 01 00 00 7C B6 }
		$f = {83 c4 0c 53 53 6a 03 53 6a 03 68 00 00 00 c0}

	condition:
		($a and $b) or $c or $d or ($openPhysicalDiskOverwriteWithZeros and $f)
}
