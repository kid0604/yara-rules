rule BlackTech_iam_downloader
{
	meta:
		description = "iam downloader malware in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "d8500672e293ef4918ff77708c5b82cf34d40c440d5a4b957a5dbd3f3420fdc4"
		os = "windows"
		filetype = "executable"

	strings:
		$fs30 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 48 08 }
		$com1 = { 81 ?? ?? 58 09 00 00 }
		$com2 = { 81 ?? ?? 5D 09 00 00 }
		$com3 = { 81 ?? ?? 5F 09 00 00 }
		$com4 = { C7 ?? ?? 6E 09 00 00 }
		$send1 = { C7 ?? 6D 09 00 00 }
		$send2 = { C7 ?? ?? 92 5A 76 5D }
		$send3 = { C7 ?? ?? 02 77 00 00 }
		$mutex = "i am mutex!" ascii
		$api1 = { 68 8E 4E 0E EC }
		$api2 = { 68 B0 49 2D DB }
		$api3 = { 68 45 A0 E4 4E }

	condition:
		$fs30 and all of ($com*) or all of ($send*) or ($mutex and all of ($api*))
}
