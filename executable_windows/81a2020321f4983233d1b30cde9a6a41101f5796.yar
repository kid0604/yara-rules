import "pe"

rule Agent_BTZ_Proxy_DLL_1
{
	meta:
		description = "Detects Agent-BTZ Proxy DLL - activeds.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
		date = "2017-08-07"
		hash1 = "9c163c3f2bd5c5181147c6f4cf2571160197de98f496d16b38c7dc46b5dc1426"
		hash2 = "628d316a983383ed716e3f827720915683a8876b54677878a7d2db376d117a24"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Modules" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them and pe.exports("Entry"))
}
