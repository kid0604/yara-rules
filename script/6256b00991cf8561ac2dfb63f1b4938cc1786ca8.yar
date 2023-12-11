rule webshell_config_myxx_zend
{
	meta:
		description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash1 = "e0354099bee243702eb11df8d0e046df"
		hash2 = "591ca89a25f06cf01e4345f98a22845c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"

	condition:
		all of them
}
