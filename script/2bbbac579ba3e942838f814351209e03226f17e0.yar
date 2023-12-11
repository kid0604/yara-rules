rule WebShell_go_shell
{
	meta:
		description = "PHP Webshells Github Archive - file go-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "#change this password; for power security - delete this file =)" fullword
		$s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword
		$s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword
		$s12 = "print << \"[kalabanga]\";" fullword
		$s13 = "<title>GO.cgi</title>" fullword

	condition:
		1 of them
}
