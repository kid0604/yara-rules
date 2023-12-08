rule CN_Honker_Webshell_PHP_php4
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "179975f632baff6ee4d674fe3fabc324724fee9e"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "nc -l -vv -p port(" ascii

	condition:
		uint16(0)==0x4850 and filesize <1KB and all of them
}
