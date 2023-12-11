rule SoakSoak_Infected_Wordpress
{
	meta:
		description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
		reference = "http://goo.gl/1GzWUX"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/12/15"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
		$s1 = "function FuncQueueObject()" ascii fullword
		$s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword

	condition:
		all of ($s*)
}
