rule php_reverse_shell_2 : webshell
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "025db3c3473413064f0606d93d155c7eb5049c42"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
		$s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii

	condition:
		filesize <10KB and all of them
}
