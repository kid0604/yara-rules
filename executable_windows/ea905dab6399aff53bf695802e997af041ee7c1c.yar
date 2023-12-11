rule MANSORY_ransomware
{
	meta:
		description = "Detect the risk of Ransomware Nemty Rule 5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "main.CTREncrypt" fullword ascii
		$s2 = "main.GenerateRandomBytes" fullword ascii
		$s3 = "idle: .MANSORY" ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 2 of them
}
