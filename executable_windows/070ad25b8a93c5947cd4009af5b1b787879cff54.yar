rule Windows_Trojan_Trickbot_1473f0b4
{
	meta:
		author = "Elastic Security"
		id = "1473f0b4-a6b5-4b19-a07e-83d32a7e44a0"
		fingerprint = "15438ae141a2ac886b1ba406ba45119da1a616c3b2b88da3f432253421aa8e8b"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets mailsearcher64.dll module"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "9cfb441eb5c60ab1c90b58d4878543ee554ada2cceee98d6b867e73490d30fec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "mailsearcher.dll" ascii fullword
		$a2 = "%s/%s/%s/send/" wide fullword
		$a3 = "Content-Disposition: form-data; name=\"list\"" ascii fullword
		$a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autostart>no</autostart><autoconf><conf ctl=\"SetConf\" file=\"mail"
		$a5 = "eriod=\"60\"/></autoconf></moduleconfig>" ascii fullword
		$a6 = "=Waitu H" ascii fullword
		$a7 = "Content-Length: %d" ascii fullword

	condition:
		2 of ($a*)
}
