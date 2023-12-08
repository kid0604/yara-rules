rule WebShell_php_webshells_lostDC
{
	meta:
		description = "PHP Webshells Github Archive - file lostDC.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"
		os = "linux, windows"
		filetype = "script"

	strings:
		$s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';" fullword
		$s4 = "header ( \"Content-Description: Download manager\" );" fullword
		$s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
		$s9 = "if (mkdir($_POST['dir'], 0777) == false) {" fullword
		$s12 = "$ret = shellexec($command);" fullword

	condition:
		2 of them
}
