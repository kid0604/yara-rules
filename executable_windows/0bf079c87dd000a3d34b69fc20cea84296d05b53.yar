rule Windows_Trojan_Trickbot_0114d469
{
	meta:
		author = "Elastic Security"
		id = "0114d469-8731-4f4f-8657-49cded5efadb"
		fingerprint = "4f1fa072f4ba577d590bb8946ea9b9774aa291cb2406f13be5932e97e8e760c6"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets systeminfo64.dll module containing functionality use to retrieve system information"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "083CB35A7064AA5589EFC544AC1ED1B04EC0F89F0E60383FCB1B02B63F4117E9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "<user>%s</user>" wide fullword
		$a2 = "<service>%s</service>" wide fullword
		$a3 = "<users>" wide fullword
		$a4 = "</users>" wide fullword
		$a5 = "%s%s%s</general>" wide fullword
		$a6 = "<program>%s</program>" wide fullword
		$a7 = "<moduleconfig><autostart>no</autostart><limit>2</limit></moduleconfig>" ascii fullword
		$a8 = "<cpu>%s</cpu>" wide fullword
		$a9 = "<ram>%s</ram>" wide fullword
		$a10 = "</installed>" wide fullword
		$a11 = "<installed>" wide fullword
		$a12 = "<general>" wide fullword
		$a13 = "SELECT * FROM Win32_Processor" wide fullword
		$a14 = "SELECT * FROM Win32_OperatingSystem" wide fullword
		$a15 = "SELECT * FROM Win32_ComputerSystem" wide fullword

	condition:
		6 of ($a*)
}
