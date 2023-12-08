rule CN_Honker_Alien_iispwd
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iispwd.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5d157a1b9644adbe0b28c37d4022d88a9f58cedb"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "set IIs=objservice.GetObject(\"IIsWebServer\",childObjectName)" fullword ascii
		$s1 = "wscript.echo \"from : http://www.xxx.com/\" &vbTab&vbCrLf" fullword ascii

	condition:
		filesize <3KB and all of them
}
