import "pe"

rule MALWARE_Win_KillMBR
{
	meta:
		author = "ditekSHen"
		description = "Detects KillMBR"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\\\.\\PhysicalDrive" ascii
		$s2 = "/logger.php" ascii
		$s3 = "Ooops! Your MBR was been rewritten" ascii
		$s4 = "No, this ransomware dont encrypt your files, erases it" ascii

	condition:
		uint16(0)==0x5a4d and (2 of them and #s1>10)
}
