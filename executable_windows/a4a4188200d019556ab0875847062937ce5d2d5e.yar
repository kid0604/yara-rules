import "pe"

rule ME_Campaign_Malware_2
{
	meta:
		description = "Detects malware from Middle Eastern campaign reported by Talos"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
		date = "2018-02-07"
		hash1 = "76a9b603f1f901020f65358f1cbf94c1a427d9019f004a99aa8bff1dea01a881"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "QuickAssist.exe" fullword wide
		$s2 = "<description>Microsoft Modern Sharing Solution</description>" fullword ascii
		$s3 = "GBEWCWA" fullword ascii
		$s4 = "name=\"QuickAssist\" " fullword ascii
		$s5 = "Cimzal" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="b06055e6cc2a804111ab6964df1ca4ae" or 4 of them )
}
