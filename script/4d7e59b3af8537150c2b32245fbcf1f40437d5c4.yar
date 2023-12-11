rule WebShell_webshells_zehir4
{
	meta:
		description = "Webshells Github Archive - file zehir4"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "788928ae87551f286d189e163e55410acbb90a64"
		score = 55
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
		$s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"

	condition:
		1 of them
}
