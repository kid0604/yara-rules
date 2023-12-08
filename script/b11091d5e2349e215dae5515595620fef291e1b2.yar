rule CN_Honker_Alien_command
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file command.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5896b74158ef153d426fba76c2324cd9c261c709"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "for /d %i in (E:\\freehost\\*) do @echo %i" fullword ascii
		$s1 = "/c \"C:\\windows\\temp\\cscript\" C:\\windows\\temp\\iis.vbs" fullword ascii

	condition:
		filesize <8KB and all of them
}
