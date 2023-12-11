import "pe"

rule APT_GreyEnergy_Malware_Oct18_3
{
	meta:
		description = "Detects samples from Grey Energy report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
		date = "2018-10-17"
		hash1 = "0db5e5b68dc4b8089197de9c1e345056f45c006b7b487f7d8d57b49ae385bad0"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "USQTUNPPQONOPOQUMSNUTRMRRLVPUOPMROPMPMQTPNPONVUOUQOMMNNSRSRQQVTPPRSSNVSTURTMMOPTONSQTOMONQVMQNUSONTQTUTSRRPVTONUQNORQMRRNRUSPS" fullword ascii
		$x2 = "tEMPiuP" fullword ascii
		$x3 = "sryCEMieye" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of them
}
