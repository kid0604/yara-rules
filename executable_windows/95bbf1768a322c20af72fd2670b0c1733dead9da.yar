import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EnvVarScheduledTasks
{
	meta:
		author = "ditekSHen"
		description = "detects Windows exceutables potentially bypassing UAC (ab)using Environment Variables in Scheduled Tasks"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii wide
		$s2 = "\\Environment" ascii wide
		$s3 = "schtasks" ascii wide
		$s4 = "/v windir" ascii wide

	condition:
		all of them
}
