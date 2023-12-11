rule Bladabindi_Malware_B64
{
	meta:
		description = "Detects Bladabindi Malware using Base64 encoded strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-10-08"
		hash1 = "dda668b0792b7679979e61f2038cf9a8ec39415cc161be00d2c8301e7d48768d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "XHN5c3RlbTMyXA==" fullword ascii
		$s2 = "RXhlY3V0ZSBFUlJPUg==" fullword ascii
		$s3 = "dHJvamFuLmV4ZQ==" fullword ascii
		$s4 = "VXBkYXRlIEVSUk9S" fullword ascii
		$s5 = "RG93bmxvYWQgRVJST1I=" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 1 of them
}
