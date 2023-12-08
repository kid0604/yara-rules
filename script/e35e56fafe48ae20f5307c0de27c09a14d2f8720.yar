rule WebShell_PhpSpy_Ver_2006
{
	meta:
		description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
		$s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
		$s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
		$s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"

	condition:
		1 of them
}
