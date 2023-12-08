import "pe"

rule apt_hellsing_installer
{
	meta:
		Author = "Costin Raiu, Kaspersky Lab"
		Date = "2015-04-07"
		Description = "detection for Hellsing xweber/msger installers"
		Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"
		description = "Detection for Hellsing xweber/msger installers"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$cmd = "cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f \"%s\""
		$a1 = "xweber_install_uac.exe"
		$a2 = "system32\\cmd.exe" wide
		$a4 = "S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y="
		$a5 = "S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg="
		$a6 = "7dqm2ODf5N/Y2N/m6+br3dnZpunl44g="
		$a7 = "vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw=="
		$a8 = "vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSI Njl2tyI"
		$a9 = "C:\\Windows\\System32\\sysprep\\sysprep.exe" wide
		$a10 = "%SystemRoot%\\system32\\cmd.exe" wide
		$a11 = "msger_install.dll"
		$a12 = {00 65 78 2E 64 6C 6C 00}

	condition:
		($mz at 0) and ($cmd and (2 of ($a*))) and filesize <500000
}
