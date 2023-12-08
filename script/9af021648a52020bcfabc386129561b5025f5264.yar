rule FeliksPack3___PHP_Shells_ssh
{
	meta:
		description = "Webshells Auto-generated - file ssh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1aa5307790d72941589079989b4f900e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "eval(gzinflate(str_rot13(base64_decode('"

	condition:
		all of them
}
