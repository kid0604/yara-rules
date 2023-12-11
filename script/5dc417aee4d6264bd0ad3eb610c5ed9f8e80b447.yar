rule webshell_c99_madnet_smowu
{
	meta:
		description = "Web Shell - file smowu.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3aaa8cad47055ba53190020311b0fb83"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "//Authentication" fullword
		$s1 = "$login = \"" fullword
		$s2 = "eval(gzinflate(base64_decode('"
		$s4 = "//Pass"
		$s5 = "$md5_pass = \""
		$s6 = "//If no pass then hash"

	condition:
		all of them
}
