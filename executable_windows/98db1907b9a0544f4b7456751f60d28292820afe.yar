import "pe"

rule Destructive_Ransomware_Gen1
{
	meta:
		description = "Detects destructive malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
		date = "2018-02-12"
		hash1 = "ae9a4e244a9b3c77d489dee8aeaf35a7c3ba31b210e76d81ef2e91790f052c85"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
		$x2 = "delete shadows /all /quiet" fullword wide
		$x3 = "delete catalog -quiet" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}
