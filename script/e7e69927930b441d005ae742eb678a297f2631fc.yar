rule webshell_webshells_new_make2
{
	meta:
		description = "Web shells - generated from file make2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		hash = "9af195491101e0816a263c106e4c145e"
		score = 50
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"

	condition:
		all of them
}
