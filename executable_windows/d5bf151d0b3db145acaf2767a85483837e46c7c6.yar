rule Windows_Trojan_CobaltStrike_417239b5
{
	meta:
		author = "Elastic Security"
		id = "417239b5-cf2d-4c85-a022-7a8459c26793"
		fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC token module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
		$a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
		$a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
		$b1 = "$pdata$is_admin_already" ascii fullword
		$b2 = "$unwind$is_admin" ascii fullword
		$b3 = "$pdata$is_admin" ascii fullword
		$b4 = "$unwind$is_admin_already" ascii fullword
		$b5 = "$pdata$RunAsAdmin" ascii fullword
		$b6 = "$unwind$RunAsAdmin" ascii fullword
		$b7 = "is_admin_already" ascii fullword
		$b8 = "is_admin" ascii fullword
		$b9 = "process_walk" ascii fullword
		$b10 = "get_current_sess" ascii fullword
		$b11 = "elevate_try" ascii fullword
		$b12 = "RunAsAdmin" ascii fullword
		$b13 = "is_ctfmon" ascii fullword
		$c1 = "_is_admin_already" ascii fullword
		$c2 = "_is_admin" ascii fullword
		$c3 = "_process_walk" ascii fullword
		$c4 = "_get_current_sess" ascii fullword
		$c5 = "_elevate_try" ascii fullword
		$c6 = "_RunAsAdmin" ascii fullword
		$c7 = "_is_ctfmon" ascii fullword
		$c8 = "_reg_query_dword" ascii fullword
		$c9 = ".drectve" ascii fullword
		$c10 = "_is_candidate" ascii fullword
		$c11 = "_SpawnAsAdmin" ascii fullword
		$c12 = "_SpawnAsAdminX64" ascii fullword

	condition:
		1 of ($a*) or 9 of ($b*) or 7 of ($c*)
}
