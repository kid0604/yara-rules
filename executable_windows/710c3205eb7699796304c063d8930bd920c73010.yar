import "pe"

rule APT_Thrip_Sample_Jun18_15
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "231c569f11460a12b171f131c40a6f25d8416954b35c28ae184aba8a649d9786"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\cmd.exe /c %s" fullword ascii
		$s2 = "CryptBase.dll" fullword ascii
		$s3 = "gupdate.exe" fullword ascii
		$s4 = "wusa.exe" fullword ascii
		$s5 = " %s %s /quiet /extract:%s\\%s\\" ascii
		$s6 = "%s%s.dll.cab" fullword ascii
		$s7 = "%s\\%s\\%s%s %s" fullword ascii
		$s8 = "%s\\%s\\%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="f6ec70a295000ab0a753aa708e9439b4" or 6 of them )
}
