import "pe"

rule APT_TA18_149A_Joanap_Sample1
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		date = "2018-05-30"
		hash1 = "ea46ed5aed900cd9f01156a1cd446cbb3e10191f9f980e9f710ea1c20440c781"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd.exe /q /c net share adnim$" ascii
		$x2 = "\\\\%s\\adnim$\\system32\\%s" fullword ascii
		$s1 = "SMB_Dll.dll" fullword ascii
		$s2 = "%s User or Password is not correct!" fullword ascii
		$s3 = "perfw06.dat" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="f0087d7b90876a2769f2229c6789fcf3" or 1 of ($x*) or 2 of them )
}
