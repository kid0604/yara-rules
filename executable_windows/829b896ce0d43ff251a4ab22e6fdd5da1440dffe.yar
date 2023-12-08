import "pe"

rule MAL_CN_FlyStudio_May18_1
{
	meta:
		description = "Detects malware / hacktool detected in May 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-05-11"
		hash1 = "b85147366890598518d4f277d44506eef871fd7fc6050d8f8e68889cae066d9e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
		$s2 = "www.cfyhack.cn" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and (pe.imphash()=="65ae5cf17140aeaf91e3e9911da0ee3e" or 1 of them )
}
