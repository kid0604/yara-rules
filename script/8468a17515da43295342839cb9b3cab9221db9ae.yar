import "pe"

rule MALWARE_Win_PWSH_PoshWiFiStealer
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell PoshWiFiStealer"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "netsh wlan export profile" ascii
		$s2 = "Send-MailMessage" ascii
		$u1 = "https://github.com/axel05869/Wifi-Grab" ascii
		$u2 = "/exploitechx/wifi-password-extractor" ascii

	condition:
		all of ($s*) or all of ($u*)
}
