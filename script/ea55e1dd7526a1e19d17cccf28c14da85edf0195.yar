rule webshell_PHP_404
{
	meta:
		description = "Web Shell - file 404.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "078c55ac475ab9e028f94f879f548bca"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"

	condition:
		all of them
}
