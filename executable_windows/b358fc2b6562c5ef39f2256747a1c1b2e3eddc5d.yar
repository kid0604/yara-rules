import "pe"

rule Slingshot_APT_Malware_3
{
	meta:
		description = "Detects malware from Slingshot APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/apt-slingshot/84312/"
		date = "2018-03-09"
		hash1 = "fa513c65cded25a7992e2b0ab03c5dd5c6d0fc2282cd64a1e11a387a3341ce18"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "chmhlpr.dll" fullword ascii
		$s2 = "%hc%hc%hc%hc" fullword ascii
		$s3 = "%hc%hc%hc=" fullword ascii
		$s4 = "%hc%hc==" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.imphash()=="2f3b3df466e24e0792e0e90d668856bc" or pe.exports("dll_u") or ($a1 and 2 of ($s*)))
}
