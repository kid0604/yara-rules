rule CN_Honker_Webshell_PHP_php7
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii
		$s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii

	condition:
		filesize <300KB and all of them
}
