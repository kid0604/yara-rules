rule CN_Honker_Webshell_PHP_php3
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php3.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e2924cb0537f4cdfd6f1bd44caaaf68a73419b9d"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii
		$s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii

	condition:
		filesize <8KB and all of them
}
