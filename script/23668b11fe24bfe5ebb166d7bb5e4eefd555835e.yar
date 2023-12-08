rule webshell_phpkit_0_1a_odd
{
	meta:
		description = "Web Shell - file odd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3c30399e7480c09276f412271f60ed01"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "include('php://input');" fullword
		$s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
		$s4 = "// uses include('php://input') to execute arbritary code" fullword
		$s5 = "// php://input based backdoor" fullword

	condition:
		2 of them
}
