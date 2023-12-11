import "pe"

rule MAL_AirdViper_Sample_Apr18_1
{
	meta:
		description = "Detects Arid Viper malware sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-05-04"
		hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
		$x2 = "daenerys=%s&" ascii
		$x3 = "betriebssystem=%s&anwendung=%s&AV=%s" ascii
		$s1 = "Taskkill /IM  %s /F &  %s" fullword ascii
		$s2 = "/api/primewire/%s/requests/macKenzie/delete" fullword ascii
		$s3 = "\\TaskWindows.exe" ascii
		$s4 = "MicrosoftOneDrives.exe" fullword ascii
		$s5 = "\\SeanSansom.txt" ascii

	condition:
		uint16(0)==0x5a4d and filesize <6000KB and (1 of ($x*) or 4 of them )
}
