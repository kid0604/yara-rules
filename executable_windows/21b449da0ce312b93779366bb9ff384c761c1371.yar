import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_fodhelper
{
	meta:
		author = "ditekSHen"
		description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\software\\classes\\ms-settings\\shell\\open\\command" ascii wide nocase
		$s2 = "DelegateExecute" ascii wide
		$s3 = "fodhelper" ascii wide
		$s4 = "ConsentPromptBehaviorAdmin" ascii wide

	condition:
		all of them
}
