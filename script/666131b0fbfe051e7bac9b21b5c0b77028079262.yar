rule webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz
{
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash2 = "42f211cec8032eb0881e87ebdb3d7224"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "0712e3dc262b4e1f98ed25760b206836"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
		$s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"

	condition:
		all of them
}
