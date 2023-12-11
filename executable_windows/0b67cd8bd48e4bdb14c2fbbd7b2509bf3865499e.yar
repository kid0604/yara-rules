rule CN_Honker_WebCruiserWVS
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebCruiserWVS.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "6c90a9ed4c8a141a343dab1b115cc840a7190304"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "id:uid:user:username:password:access:account:accounts:admin_id:admin_name:admin_" ascii
		$s1 = "Created By WebCruiser - Web Vulnerability Scanner http://sec4app.com" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
