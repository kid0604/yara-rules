rule php_reverse_shell : webshell
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
		$s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
		$s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii

	condition:
		filesize <15KB and all of them
}
