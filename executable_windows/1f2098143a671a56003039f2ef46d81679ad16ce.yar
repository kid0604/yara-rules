import "pe"

rule antivm_bios
{
	meta:
		author = "x0r"
		description = "AntiVM checks for Bios version"
		version = "0.2"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "HARDWARE\\DESCRIPTION\\System" nocase
		$p2 = "HARDWARE\\DESCRIPTION\\System\\BIOS" nocase
		$c1 = "RegQueryValue"
		$r1 = "SystemBiosVersion"
		$r2 = "VideoBiosVersion"
		$r3 = "SystemManufacturer"

	condition:
		1 of ($p*) and 1 of ($c*) and 1 of ($r*)
}
