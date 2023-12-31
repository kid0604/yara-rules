import "pe"

rule MALWARE_Win_TRAT
{
	meta:
		author = "ditekSHen"
		description = "TRAT payload"
		clamav_sig = "MALWARE.Win.Trojan.TRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "^STEAM_0:[0-1]:([0-9]{1,10})$" fullword wide
		$s2 = "^7656119([0-9]{10})$" fullword wide
		$s3 = "Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)" ascii
		$s4 = "\"schtasks\", \"/delete /tn UpdateWindows /f\");" ascii
		$s5 = "ProcessWindowStyle.Hidden" ascii
		$s6 = "+<>c+<<ListCommands>" ascii
		$s7 = "//B //Nologo *Y" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
