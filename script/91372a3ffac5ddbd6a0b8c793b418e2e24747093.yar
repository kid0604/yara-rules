import "math"
import "pe"

rule StoneDrill_Service_Install
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Rule to detect Batch file from StoneDrill report"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "127.0.0.1 >nul && sc config" ascii
		$s2 = "LocalService\" && ping -n" ascii fullword
		$s3 = "127.0.0.1 >nul && sc start" ascii fullword
		$s4 = "sc config NtsSrv binpath= \"C:\\WINDOWS\\system32\ntssrvr64.exe" ascii

	condition:
		2 of them and filesize <500
}
