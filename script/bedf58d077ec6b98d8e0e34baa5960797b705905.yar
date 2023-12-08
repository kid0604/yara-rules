rule webadmin
{
	meta:
		description = "Webshells Auto-generated - file webadmin.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3a90de401b30e5b590362ba2dde30937"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"

	condition:
		all of them
}
