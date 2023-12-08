rule Dotico_PHP_webshell : webshell
{
	meta:
		description = ".ico PHP webshell - file <eight-num-letter-chars>.ico"
		author = "Luis Fueris"
		reference = "https://rankinstudio.com/Drupal_ico_index_hack"
		date = "2019/12/04"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php = "<?php" ascii
		$regexp = /basename\/\*[a-z0-9]{,6}\*\/\(\/\*[a-z0-9]{,5}\*\/trim\/\*[a-z0-9]{,5}\*\/\(\/\*[a-z0-9]{,5}\*\//

	condition:
		$php at 0 and $regexp and filesize >70KB and filesize <110KB
}
