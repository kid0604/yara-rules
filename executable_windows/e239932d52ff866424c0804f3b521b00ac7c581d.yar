import "pe"

rule APT_Thrip_Sample_Jun18_12
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "33c01d3266fe6a70e8785efaf10208f869ae58a17fd9cdb2c6995324c9a01062"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "pGlobal->nOSType==64--%s\\cmd.exe %s" fullword ascii
		$s2 = "httpcom.log" fullword ascii
		$s3 = "\\CryptBase.dll" ascii
		$s4 = "gupdate.exe" fullword ascii
		$s5 = "wusa.exe" fullword ascii
		$s6 = " %s %s /quiet /extract:%s\\%s\\" ascii
		$s7 = "%s%s.dll.cab" fullword ascii
		$s8 = "/c %s\\%s\\%s%s %s" fullword ascii
		$s9 = "ReleaseEvildll" fullword ascii
		$s0 = "%s\\%s\\%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 6 of them
}
