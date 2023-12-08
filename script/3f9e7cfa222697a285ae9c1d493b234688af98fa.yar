rule CN_Honker_Webshell_PHP_BlackSky
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a60a599c6c8b6a6c0d9da93201d116af257636d7"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "eval(gzinflate(base64_decode('" ascii
		$s1 = "B1ac7Sky-->" fullword ascii

	condition:
		filesize <641KB and all of them
}
