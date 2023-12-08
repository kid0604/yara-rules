rule WebShell_zehir4_asp_php
{
	meta:
		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
		$s11 = "frames.byZehir.document.execCommand("
		$s15 = "frames.byZehir.document.execCommand(co"

	condition:
		2 of them
}
