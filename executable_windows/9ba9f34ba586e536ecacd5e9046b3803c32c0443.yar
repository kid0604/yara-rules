import "pe"

rule MALWARE_Win_Trojan_ExpressCMS
{
	meta:
		author = "ditekSHen"
		description = "Detects ExpressCMS"
		clamav_sig = "MALWARE.Win.Trojan.ExpressCMS"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/click.php?cnv_id=" fullword wide
		$s2 = "/click.php?key=" wide
		$s3 = "jdlnb" fullword wide
		$s4 = "Gkjfdshfkjjd: dsdjdsjdhv" fullword wide
		$s5 = "--elevated" fullword wide
		$s6 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%d" wide
		$s7 = "\\Microsoft\\Manager.exe" fullword wide
		$s8 = "\\Microsoft\\svchost.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and 6 of them
}
