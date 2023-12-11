rule webshell_r57_1_4_0
{
	meta:
		description = "Web Shell - file r57.1.4.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "574f3303e131242568b0caf3de42f325"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "@ini_set('error_log',NULL);" fullword
		$s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s7 = "@ini_restore(\"disable_functions\");" fullword
		$s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword

	condition:
		all of them
}
