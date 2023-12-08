import "pe"

rule TROJAN_Notepad_shell_crew : Trojan
{
	meta:
		author = "RSA_IR"
		Date = "4Jun13"
		File = "notepad.exe v 1.1"
		MD5 = "106E63DBDA3A76BEEB53A8BBD8F98927"
		description = "Detects the presence of the TROJAN_Notepad_shell_crew malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "75BAA77C842BE168B0F66C42C7885997"
		$s2 = "B523F63566F407F3834BCC54AAA32524"

	condition:
		$s1 or $s2
}
