rule webshell_PHP_150
{
	meta:
		description = "Web Shell - file 150.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "400c4b0bed5c90f048398e1d268ce4dc"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "HJ3HjqxclkZfp"
		$s1 = "<? eval(gzinflate(base64_decode('" fullword

	condition:
		all of them
}
