import "pe"

rule Reaver3_Malware_Nov17_3
{
	meta:
		description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
		date = "2017-11-11"
		modified = "2023-01-06"
		hash1 = "18ac3b14300ecfeed4b64a844c16dccb06b0e3513d0954d6c6182f2ea14e4c92"
		hash2 = "c0f8bb77284b96e07cab1c3fab8800b1bbd030720c74628c4ee5666694ef903d"
		hash3 = "c906250e0a4c457663e37119ebe1efa1e4b97eef1d975f383ac3243f9f09908c"
		hash4 = "1fcda755e8fa23d27329e4bc0443a82e1c1e9a6c1691639db256a187365e4db1"
		hash5 = "d560f44188fb56d3abb11d9508e1167329470de19b811163eb1167534722e666"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "winhelp.dat" fullword ascii
		$s2 = "\\microsoft\\Credentials\\" ascii
		$s3 = "~Update.lnk" fullword ascii
		$s4 = "winhelp.cpl" fullword ascii
		$s5 = "\\services\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="8ee521b2316ddd6af1679eac9f5ed77b" or 4 of them )
}
