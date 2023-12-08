rule webshell_simple_backdoor
{
	meta:
		description = "Web Shell - file simple-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "if(isset($_REQUEST['cmd'])){" fullword
		$s4 = "system($cmd);" fullword

	condition:
		2 of them
}
