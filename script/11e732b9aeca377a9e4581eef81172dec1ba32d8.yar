rule Suspicious_Script_Running_from_HTTP
{
	meta:
		description = "Detects a suspicious "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
		score = 50
		date = "2017-08-20"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "cmd /C script:http://" ascii nocase
		$s2 = "cmd /C script:https://" ascii nocase
		$s3 = "cmd.exe /C script:http://" ascii nocase
		$s4 = "cmd.exe /C script:https://" ascii nocase

	condition:
		1 of them
}
