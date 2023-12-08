import "pe"

rule CN_disclosed_20180208_Mal4
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		date = "2018-02-08"
		hash1 = "f7549c74f09be7e4dbfb64006e535b9f6d17352e236edc2cdb102ec3035cf66e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Microsoft .Net Framework COM+ Support" fullword ascii
		$s2 = "Microsoft .NET and Windows XP COM+ Integration with SOAP" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them and pe.exports("SPACE")
}
