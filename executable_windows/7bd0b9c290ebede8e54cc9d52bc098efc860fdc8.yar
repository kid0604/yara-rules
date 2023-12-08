import "pe"

rule MALWARE_Win_Hello
{
	meta:
		author = "ditekSHen"
		description = "Hunt for Hello / WickrMe ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DeleteBackupFiles" ascii wide
		$s2 = "GetEncryptFiles" ascii wide
		$s3 = "DeleteVirtualDisks" ascii wide
		$s4 = "DismountVirtualDisks" ascii wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
