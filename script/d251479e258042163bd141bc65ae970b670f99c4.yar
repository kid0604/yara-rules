rule FSO_s_remview
{
	meta:
		description = "Webshells Auto-generated - file remview.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b4a09911a5b23e00b55abe546ded691c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
		$s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
		$s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"

	condition:
		all of them
}
