import "pe"

rule MALWARE_Win_Multi_Family_InfoStealer
{
	meta:
		author = "ditekSHen"
		description = "Detects Prynt, WorldWind, DarkEye, Stealerium and ToxicEye / TelegramRAT infostealers"
		os = "windows"
		filetype = "executable"

	strings:
		$n1 = /Prynt|WorldWind|DarkEye(\s)?Stealer/ ascii wide
		$n2 = "Stealerium" ascii wide
		$x1 = "@FlatLineStealer" ascii wide
		$x2 = "@CashOutGangTalk" ascii wide
		$x3 = /\.Target\.(Passwords|Messengers|Browsers|VPN|Gaming)\./ ascii
		$x4 = /\.Modules\.(Keylogger|Implant|Passwords|Messengers|Browsers|VPN|Gaming|Clipper)\./ ascii
		$s1 = "Timeout /T 2 /Nobreak" fullword wide
		$s2 = /---\s(AntiAnalysis|WebcamScreenshot|Keylogger|Clipper)/ wide
		$s3 = "Downloading file: \"{file}\"" wide
		$s4 = "/bot{0}/getUpdates?offset={1}" wide
		$s5 = "send command to bot!" wide
		$s6 = " *Keylogger " fullword wide
		$s7 = "*Stealer" wide
		$s8 = "Bot connected" wide
		$s9 = "### {0} ### ({1})" wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
