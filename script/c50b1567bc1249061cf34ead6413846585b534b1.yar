rule INDICATOR_KB_ID_PowerShellWiFiStealer
{
	meta:
		author = "ditekShen"
		description = "Detects email accounts used for exfiltration observed in PowerShellWiFiStealer"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "hajdebebreidekreide@gmail.com" ascii wide nocase
		$s2 = "usb@pterobot.net" ascii wide nocase
		$s3 = "umairdadaber@gmail.com" ascii wide nocase
		$s4 = "mrumairok@gmail.com" ascii wide nocase
		$s5 = "credsenderbot@gmail.com" ascii wide nocase
		$s6 = "easywareytb@gmail.com" ascii wide nocase

	condition:
		any of them
}
