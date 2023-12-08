rule WebShell_php_webshells_README
{
	meta:
		description = "PHP Webshells Github Archive - file README.md"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ef2c567b4782c994db48de0168deb29c812f7204"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
		$s1 = "php-webshells" fullword

	condition:
		all of them
}
