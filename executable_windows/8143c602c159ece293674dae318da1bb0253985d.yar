import "pe"

rule wannacry_static_ransom : wannacry_static_ransom
{
	meta:
		description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"
		author = "Blueliv"
		reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
		date = "2017-05-15"
		os = "windows"
		filetype = "executable"

	strings:
		$mutex01 = "Global\\MsWinZonesCacheCounterMutexA" ascii
		$lang01 = "m_bulgarian.wnr" ascii
		$lang02 = "m_vietnamese.wnry" ascii
		$startarg01 = "StartTask" ascii
		$startarg02 = "TaskStart" ascii
		$startarg03 = "StartSchedule" ascii
		$wcry01 = "WanaCrypt0r" ascii wide
		$wcry02 = "WANACRY" ascii
		$wcry03 = "WANNACRY" ascii
		$wcry04 = "WNCRYT" ascii wide
		$forig01 = ".wnry\x00" ascii
		$fvar01 = ".wry\x00" ascii

	condition:
		($mutex01 or any of ($lang*)) and ($forig01 or all of ($fvar*)) and any of ($wcry*) and any of ($startarg*)
}
