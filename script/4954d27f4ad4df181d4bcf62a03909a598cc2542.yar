rule WebShell_simple_backdoor
{
	meta:
		description = "PHP Webshells Github Archive - file simple-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s3 = "        echo \"</pre>\";" fullword
		$s4 = "        $cmd = ($_REQUEST['cmd']);" fullword
		$s5 = "        echo \"<pre>\";" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s7 = "        die;" fullword
		$s8 = "        system($cmd);" fullword

	condition:
		all of them
}
