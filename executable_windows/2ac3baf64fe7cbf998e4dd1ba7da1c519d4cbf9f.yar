import "pe"

rule MAL_Beacon_Unknown_Feb24_1
{
	meta:
		description = "Detects malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709 "
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		date = "2024-02-23"
		score = 75
		hash1 = "6e8f83c88a66116e1a7eb10549542890d1910aee0000e3e70f6307aae21f9090"
		hash2 = "b0adf3d58fa354dbaac6a2047b6e30bc07a5460f71db5f5975ba7b96de986243"
		hash3 = "c0f7970bed203a5f8b2eca8929b4e80ba5c3276206da38c4e0a4445f648f3cec"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Driver.dll" wide fullword
		$s2 = "X l.dlT" ascii fullword
		$s3 = "$928c7481-dd27-8e23-f829-4819aefc728c" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 3 of ($s*)
}
