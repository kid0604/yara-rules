import "pe"

rule MALWARE_Osx_DazzleSpy
{
	meta:
		author = "ditekSHen"
		description = "Attemp at hunting for DazzleSpy"
		os = "macos"
		filetype = "executable"

	strings:
		$x1 = "/osxrk_commandline/" ascii wide nocase
		$x2 = "/Users/wangping/pangu/" ascii wide nocase
		$s1 = "heartbeat" ascii wide
		$s2 = "scanFiles" ascii wide
		$s3 = "restartCMD" ascii wide
		$s4 = "downloadFile" ascii wide
		$s5 = "RDPInfo" ascii wide

	condition:
		uint16(0)==0xfacf and ( all of ($x*) or all of ($s*) or (1 of ($x*) and 3 of ($s*)))
}
