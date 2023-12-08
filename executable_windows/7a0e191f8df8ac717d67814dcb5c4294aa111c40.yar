import "pe"

rule MALWARE_Win_BlackshadesRAT
{
	meta:
		author = "ditekSHen"
		description = "BlackshadesRAT / Cambot POS payload"
		snort_sid = "920208-920210"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bhookpl.dll" fullword wide
		$s2 = "drvloadn.dll" fullword wide
		$s3 = "drvloadx.dll" fullword wide
		$s4 = "SPY_NET_RATMUTEX" fullword wide
		$s5 = "\\dump.txt" fullword wide
		$s6 = "AUTHLOADERDEFAULT" fullword wide
		$pdb = "*\\AC:\\Users\\Admin\\Desktop_old\\Blackshades project\\bs_bot\\bots\\bot\\bs_bot.vbp" fullword wide

	condition:
		uint16(0)==0x5a4d and (4 of ($s*) or ($pdb and 2 of ($s*)))
}
