rule webshell_shell_phpspy_2006_arabicspy_hkrkoz
{
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
		hash3 = "802f5cae46d394b297482fd0c27cb2fc"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."

	condition:
		all of them
}
