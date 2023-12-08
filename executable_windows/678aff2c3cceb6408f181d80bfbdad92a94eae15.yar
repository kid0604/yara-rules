import "pe"

rule Winnti_malware_UpdateDLL
{
	meta:
		description = "Detects a Winnti malware - Update.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VTI research"
		date = "2015-10-10"
		score = 75
		hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
		hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
		hash4 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "'Wymajtec$Tima Stempijg Sarviges GA -$G2" fullword ascii
		$c2 = "AHDNEAFE1.sys" fullword ascii
		$c3 = "SOTEFEHJ3.sys" fullword ascii
		$c4 = "MainSYS64.sys" fullword ascii
		$s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" wide
		$s2 = "Update.dll" fullword ascii
		$s3 = "\\\\.\\pipe\\usbpcex%d" fullword wide
		$s4 = "\\\\.\\pipe\\usbpcg%d" fullword wide
		$s5 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" wide
		$s6 = "\\??\\pipe\\usbpcg%d" fullword wide
		$s7 = "\\??\\pipe\\usbpcex%d" fullword wide
		$s8 = "HOST: %s" fullword ascii
		$s9 = "$$$--Hello" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and ((1 of ($c*) and 3 of ($s*)) or all of ($s*))
}
