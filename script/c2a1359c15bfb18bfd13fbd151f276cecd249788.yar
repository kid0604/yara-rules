rule myshell_php_php
{
	meta:
		description = "Semi-Auto-generated  - file myshell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "62783d1db52d05b1b6ae2403a7044490"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory."
		$s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color"
		$s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$"

	condition:
		2 of them
}
