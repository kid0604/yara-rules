import "pe"

rule MALWARE_Win_HakunaMatata
{
	meta:
		author = "ditekSHen"
		description = "Detects HakunaMatata ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s2 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" wide
		$s3 = "<RSAKeyValue><Modulus>" wide
		$s4 = "HAKUNA MATATA" ascii wide
		$s5 = "EXCEPTIONAL_FILE" ascii
		$s6 = "TRIPLE_ENCRYPT" ascii
		$s7 = "FULL_ENCRYPT" ascii
		$s8 = "TARGETED_EXTENSIONS" ascii
		$s9 = "CHANGE_PROCESS_NAME" ascii
		$s10 = "KILL_APPS_ENCRYPT_AGAIN" ascii
		$s11 = "<ALL_DRIVES>b__" ascii
		$s12 = "dataToEncrypt" ascii
		$s13 = "<RECURSIVE_DIRECTORY_LOOK>" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
