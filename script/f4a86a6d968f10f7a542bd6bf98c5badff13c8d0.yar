rule DxShell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file DxShell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "33a2b31810178f4c2e71fbdeb4899244"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><"

	condition:
		1 of them
}
