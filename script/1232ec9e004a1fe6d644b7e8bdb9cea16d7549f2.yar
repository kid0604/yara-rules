rule WebShell_ZyklonShell
{
	meta:
		description = "PHP Webshells Github Archive - file ZyklonShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3fa7e6f3566427196ac47551392e2386a038d61c"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
		$s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
		$s2 = "<TITLE>404 Not Found</TITLE>" fullword
		$s3 = "<H1>Not Found</H1>" fullword

	condition:
		all of them
}
