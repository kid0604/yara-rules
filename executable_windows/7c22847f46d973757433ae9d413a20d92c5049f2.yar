import "pe"

rule Winnti_malware_Nsiproxy
{
	meta:
		description = "Detects a Winnti rootkit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-10-10"
		score = 75
		hash1 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		hash2 = "cf1e006694b33f27d7c748bab35d0b0031a22d193622d47409b6725b395bffb0"
		hash3 = "326e2cabddb641777d489a9e7a39d52c0dc2dcb1fde1762554ea162792056b6e"
		hash4 = "aff7c7478fe33c57954b6fec2095efe8f9edf5cdb48a680de9439ba62a77945f"
		hash5 = "ba7ccd027fd2c826bbe8f2145d5131eff906150bd98fe25a10fbee2c984df1b8"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Driver\\nsiproxy" wide
		$a1 = "\\Device\\StreamPortal" wide
		$a2 = "\\Device\\PNTFILTER" wide
		$s1 = "Cookie: SN=" fullword ascii
		$s2 = "\\BaseNamedObjects\\_transmition_synchronization_" wide
		$s3 = "Winqual.sys" fullword wide
		$s4 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" wide
		$s5 = "http://www.wasabii.com.tw 0" fullword ascii

	condition:
		uint16(0)==0x5a4d and $x1 and 1 of ($a*) and 2 of ($s*)
}
