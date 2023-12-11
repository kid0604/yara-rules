rule webshell_cpg_143_incl_xpl
{
	meta:
		description = "Web Shell - file cpg_143_incl_xpl.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5937b131b67d8e0afdbd589251a5e176"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
		$s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"

	condition:
		1 of them
}
