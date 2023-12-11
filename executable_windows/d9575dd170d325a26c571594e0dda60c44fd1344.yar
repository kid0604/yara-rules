import "pe"

rule APT_TA18_149A_Joanap_Sample2
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		date = "2018-05-30"
		hash1 = "077d9e0e12357d27f7f0c336239e961a7049971446f7a3f10268d9439ef67885"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%SystemRoot%\\system32\\svchost.exe -k Wmmvsvc" fullword ascii
		$s2 = "%SystemRoot%\\system32\\svchost.exe -k SCardPrv" fullword ascii
		$s3 = "%SystemRoot%\\system32\\Wmmvsvc.dll" fullword ascii
		$s4 = "%SystemRoot%\\system32\\scardprv.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="e8cd12071a8e823ebc434c8ee3e23203" or 2 of them )
}
