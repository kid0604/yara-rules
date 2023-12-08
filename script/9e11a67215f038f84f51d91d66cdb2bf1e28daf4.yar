rule webshell_PHP_co
{
	meta:
		description = "Web Shell - file co.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "62199f5ac721a0cb9b28f465a513874c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
		$s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword

	condition:
		all of them
}
