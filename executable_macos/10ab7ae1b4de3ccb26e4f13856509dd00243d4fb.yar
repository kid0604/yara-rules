import "pe"

rule MALWARE_Osx_WindTrail
{
	meta:
		author = "ditekSHen"
		description = "Detects WindTrail OSX trojan"
		clamav_sig = "MALWARE.Osx.Trojan.WindTrail"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "m_ComputerName_UserName" fullword ascii
		$s2 = "m_uploadURL" fullword ascii
		$s3 = "m_logString" fullword ascii
		$s4 = "GenrateDeviceName" fullword ascii
		$s5 = "open -a" fullword ascii
		$s6 = "AESEncryptFile:toFile:usingPassphrase:error:" fullword ascii
		$s7 = "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:" fullword ascii
		$s8 = "_kLSSharedFileListSessionLoginItems" fullword ascii
		$developerid = "Developer ID Application: warren portman (95RKE2AA8F)" ascii

	condition:
		uint16(0)==0xfacf and ( all of ($s*) or $developerid)
}
