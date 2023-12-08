rule WebShell_b374k_php
{
	meta:
		description = "PHP Webshells Github Archive - file b374k.php.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "04c99efd187cf29dc4e5603c51be44170987bce2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
		$s6 = "// password (default is: b374k)"
		$s8 = "//******************************************************************************"
		$s9 = "// b374k 2.2" fullword
		$s10 = "eval(\"?>\".gzinflate(base64_decode("

	condition:
		3 of them
}
