import "pe"

rule MALWARE_Win_PWSH_PoshKeylogger
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell PoshKeylogger"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "::GetKeyboardState" ascii
		$s2 = "GetAsyncKeyState(" ascii
		$s3 = "::MapVirtualKey(" ascii
		$s4 = "::GetAsyncKeyState" ascii
		$s5 = "Start-Sleep" ascii
		$s6 = "send-mailmessage" ascii
		$s7 = "[System.IO.File]::AppendAllText($" ascii
		$s8 = "new-object Management.Automation.PSCredential $" ascii

	condition:
		6 of them
}
