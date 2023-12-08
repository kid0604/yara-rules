rule FE_APT_Backdoor_Linux32_SLOWPULSE_1
{
	meta:
		author = "Mandiant"
		date = "2021-04-16"
		sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
		description = "Detects samples mentioned in PulseSecure report"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		os = "linux"
		filetype = "executable"

	strings:
		$sb1 = {FC b9 [4] e8 00 00 00 00 5? 8d b? [4] 8b}
		$sb2 = {f3 a6 0f 85 [4] b8 03 00 00 00 5? 5? 5?}
		$sb3 = {9c 60 e8 00 00 00 00 5? 8d [5] 85 ?? 0f 8?}
		$sb4 = {89 13 8b 51 04 89 53 04 8b 51 08 89 53 08}
		$sb5 = {8d [5] b9 [4] f3 a6 0f 8?}

	condition:
		(( uint32(0)==0x464c457f) and ( uint8(4)==1)) and all of them
}
