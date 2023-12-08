rule settings : webshell
{
	meta:
		description = "Laudanum Injector Tools - file settings.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii
		$s2 = "<li>Reverse Shell - " fullword ascii
		$s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii

	condition:
		filesize <13KB and all of them
}
