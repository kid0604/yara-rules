rule webshell_jspShell
{
	meta:
		description = "Web Shell - file jspShell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
		$s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"

	condition:
		all of them
}
