rule Windows_Trojan_CobaltStrike_7efd3c3f
{
	meta:
		author = "Elastic Security"
		id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
		fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Hashdump module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 70
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "hashdump.dll" ascii fullword
		$a2 = "hashdump.x64.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\hashdump" ascii fullword
		$a4 = "ReflectiveLoader"
		$a5 = "Global\\SAM" ascii fullword
		$a6 = "Global\\FREE" ascii fullword
		$a7 = "[-] no results." ascii fullword

	condition:
		4 of ($a*)
}
