rule webshell_phpkit_1_0_odd
{
	meta:
		description = "Web Shell - file odd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "594d1b1311bbef38a0eb3d6cbb1ab538"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "include('php://input');" fullword
		$s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
		$s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword

	condition:
		all of them
}
