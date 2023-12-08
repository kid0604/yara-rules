import "pe"

rule APT_TA18_149A_Joanap_Sample3
{
	meta:
		description = "Detects malware from TA18-149A report by US-CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-149A"
		date = "2018-05-30"
		hash1 = "a1c483b0ee740291b91b11e18dd05f0a460127acfc19d47b446d11cd0e26d717"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mssvcdll.dll" fullword ascii
		$s2 = "https://www.google.com/index.html" fullword ascii
		$s3 = "LOGINDLG" fullword wide
		$s4 = "rundll" fullword ascii
		$s5 = "%%s\\%%s%%0%dd.%%s" fullword ascii
		$s6 = "%%s\\%%s%%0%dd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="f6f7b2e00921129d18061822197111cd" or 3 of them )
}
