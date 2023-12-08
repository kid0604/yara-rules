import "pe"
import "math"

rule StoneDrill_BAT_1
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Rule to detect Batch file from StoneDrill report"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "set u100=" ascii
		$s2 = "set u200=service" ascii fullword
		$s3 = "set u800=%~dp0" ascii fullword
		$s4 = "\"%systemroot%\\system32\\%u100%\"" ascii
		$s5 = "%\" start /b %systemroot%\\system32\\%" ascii

	condition:
		uint32(0)==0x68636540 and 2 of them and filesize <500
}
