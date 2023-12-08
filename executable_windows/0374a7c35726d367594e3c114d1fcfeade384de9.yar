rule CN_Honker_SQLServer_inject_Creaked
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SQLServer_inject_Creaked.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af3c41756ec8768483a4cf59b2e639994426e2c2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://localhost/index.asp?id=2" fullword ascii
		$s2 = "Email:zhaoxypass@yahoo.com.cn<br>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <8110KB and all of them
}
