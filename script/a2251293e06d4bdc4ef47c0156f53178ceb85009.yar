rule webshell_caidao_shell_guo
{
	meta:
		description = "Web Shell - file guo.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9e69a8f499c660ee0b4796af14dc08f0"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php ($www= $_POST['ice'])!"
		$s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"

	condition:
		1 of them
}
