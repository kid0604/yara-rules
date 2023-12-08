rule CN_Honker_Without_a_trace_Wywz
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Wywz.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f443c43fde643228ee95def5c8ed3171f16daad8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Symantec\\Norton Personal Firewall\\Log\\Content.log" ascii
		$s2 = "UpdateFile=d:\\tool\\config.ini,Option\\\\proxyIp=127.0.0.1\\r\\nproxyPort=808" ascii
		$s3 = "%s\\subinacl.exe /subkeyreg \"%s\" /Grant=%s=f /Grant=everyone=f" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1800KB and all of them
}
