rule INDICATOR_RTF_Exploit_Scripting
{
	meta:
		description = "detects CVE-2017-8759 or CVE-2017-8570 weaponized RTF documents."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$clsid2 = "0003000000000000c000000000000046" ascii nocase
		$clsid3 = "4f4c45324c696e6b" ascii nocase
		$clsid4 = "OLE2Link" ascii nocase
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$ole5 = { 64 30 63 66 [0-2] 31 31 65 30 61 31 62 31 31 61 65 31 }
		$ole6 = "D0cf11E" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii
		$obj8 = "\\objclass htmlfile" ascii
		$sct1 = { 33 (43|63) (3533|3733) (3433|3633) (3532|3732) (3439|3639)( 3530|3730) (3534|3734) (3443|3643) (3435|3635) (3534|3734) }
		$sct2 = { (3737|3537) (3733|3533) (3633|3433) (3732|3532) (3639|3439) (3730|3530) (3734|3534) (3245|3265) (3733|3533) (3638|3438) (3635|3435) (3643|3443) (3643|3443) }

	condition:
		uint32(0)==0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and 1 of ($obj*) and 1 of ($sct*)
}
