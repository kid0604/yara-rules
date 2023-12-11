rule WebShell_accept_language
{
	meta:
		description = "PHP Webshells Github Archive - file accept_language.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "180b13576f8a5407ab3325671b63750adbcb62c9"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword

	condition:
		all of them
}
