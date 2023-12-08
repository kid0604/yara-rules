import "pe"

rule MALWARE_Linux_Buhti
{
	meta:
		author = "ditekSHen"
		description = "Detects Buhti Ransomware"
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = "buhtiRansom" ascii
		$x2 = "://satoshidisk.com/pay/" ascii
		$s1 = "main.encrypt_file" fullword ascii
		$s2 = "/path/to/be/encrypted" ascii
		$s3 = "Restore-My-Files.txt" ascii
		$s4 = ".buhti390625" ascii

	condition:
		uint16(0)==0x457f and ( all of ($x*) or (1 of ($x*) and 3 of ($s*)) or 5 of them )
}
