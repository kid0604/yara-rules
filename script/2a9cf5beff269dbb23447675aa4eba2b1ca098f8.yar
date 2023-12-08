rule CN_Honker_ChinaChopper_db
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file db.mdb"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af79ff2689a6b7a90a5d3c0ebe709e42f2a15597"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "http://www.maicaidao.com/server.phpcaidao" fullword wide
		$s2 = "<O>act=login</O>" fullword wide
		$s3 = "<H>localhost</H>" fullword wide

	condition:
		filesize <340KB and 2 of them
}
