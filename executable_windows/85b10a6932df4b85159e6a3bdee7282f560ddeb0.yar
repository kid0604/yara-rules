rule Windows_Trojan_Trickbot_6eb31e7b
{
	meta:
		author = "Elastic Security"
		id = "6eb31e7b-9dc3-48ff-91fe-8c584729c415"
		fingerprint = "d145b7c95bca0dc0c46a8dff60341a21dce474edd169dd0ee5ea2396dad60b92"
		creation_date = "2021-03-30"
		last_modified = "2021-10-04"
		description = "Targets DomainDll module containing functionality using LDAP to retrieve credentials and configuration information"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "3e3d82ea4764b117b71119e7c2eecf46b7c2126617eafccdfc6e96e13da973b1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "module32.dll" ascii fullword
		$a2 = "Size - %d kB" ascii fullword
		$a3 = "</moduleconfig> " ascii fullword
		$a4 = "<moduleconfig>" ascii fullword
		$a5 = "\\\\%ls\\SYSVOL\\%ls" wide fullword
		$a6 = "DomainGrabber"
		$a7 = "<autostart>yes</autostart>" ascii fullword
		$a8 = "<needinfo name=\"id\"/>" ascii fullword
		$a9 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide fullword

	condition:
		5 of ($a*)
}
