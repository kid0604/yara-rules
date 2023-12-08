import "pe"

rule APT_GreyEnergy_Malware_Oct18_4
{
	meta:
		description = "Detects samples from Grey Energy report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
		date = "2018-10-17"
		hash1 = "6974b8acf6a8f7684673b01753c3a8248a1c491900cccf771db744ca0442f96a"
		hash2 = "165a7853ef51e96ce3f88bb33f928925b24ca5336e49845fc5fc556812092740"
		hash3 = "4470e40f63443aa27187a36bbb0c2f4def42b589b61433630df842b6e365ae3d"
		hash4 = "c21cf6018c2ee0a90b9d2c401aae8071c90b5a4bc9848a94d678d77209464f79"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "iiodttd.eWt" fullword ascii
		$x2 = "irnnaar-ite-ornaa-naa-asoeienaeaanlagoeas:acnuihaaa" fullword ascii
		$x3 = "NURVNTURVORSMSPPRTQMPTTQOQRP" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="279adfbd42308a07b3131ee57d067b3e" or 1 of them )
}
