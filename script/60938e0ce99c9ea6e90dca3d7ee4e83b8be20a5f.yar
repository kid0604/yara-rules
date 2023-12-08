rule FeliksPack3___PHP_Shells_usr
{
	meta:
		description = "Webshells Auto-generated - file usr.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ade3357520325af50c9098dc8a21a024"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"

	condition:
		all of them
}
