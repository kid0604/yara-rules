rule webshell_phpspy2010
{
	meta:
		description = "Web Shell - file phpspy2010.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "14ae0e4f5349924a5047fed9f3b105c5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "eval(gzinflate(base64_decode("
		$s5 = "//angel" fullword
		$s8 = "$admin['cookiedomain'] = '';" fullword

	condition:
		all of them
}
