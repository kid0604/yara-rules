import "pe"

rule FreeMilk_APT_Mal_1
{
	meta:
		description = "Detects malware from FreeMilk campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
		date = "2017-10-05"
		hash1 = "34478d6692f8c28332751b31fd695b799d4ab36a8c12f7b728e2cb99ae2efcd9"
		hash2 = "35273d6c25665a19ac14d469e1436223202be655ee19b5b247cb1afef626c9f2"
		hash3 = "0f82ea2f92c7e906ee9ffbbd8212be6a8545b9bb0200eda09cce0ba9d7cb1313"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\milk\\Release\\milk.pdb" ascii
		$x2 = "E:\\BIG_POOH\\Project\\" ascii
		$x3 = "Windows-KB271854-x86.exe" fullword wide
		$s1 = "Windows-KB275122-x86.exe" fullword wide
		$s2 = "\\wsatra.tmp" wide
		$s3 = "%s\\Rar0tmpExtra%d.rtf" fullword wide
		$s4 = "\"%s\" help" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="108aa007b3d1b4817ff4c04d9b254b39" or 1 of ($x*) or 4 of them )
}
