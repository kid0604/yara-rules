rule WScriptShell_Case_Anomaly
{
	meta:
		description = "Detects obfuscated wscript.shell commands"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-11"
		modified = "2022-06-09"
		score = 60
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "WScript.Shell\").Run" nocase ascii wide
		$sn1 = "WScript.Shell\").Run" ascii wide
		$sn2 = "wscript.shell\").run" ascii wide
		$sn3 = "WSCRIPT.SHELL\").RUN" ascii wide
		$sn4 = "Wscript.Shell\").Run" ascii wide
		$sn5 = "WScript.shell\").Run" ascii wide

	condition:
		filesize <3000KB and #s1>#sn1+#sn2+#sn3+#sn4+#sn5
}
