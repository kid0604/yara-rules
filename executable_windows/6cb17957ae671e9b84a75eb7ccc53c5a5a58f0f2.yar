rule Windows_Trojan_Fickerstealer_cc02e75e
{
	meta:
		author = "Elastic Security"
		id = "cc02e75e-2049-4ee4-9302-e491e7dad696"
		fingerprint = "022088764645d85dd20d1ce201395b4e79e3e716723715687eaecfcbe667615e"
		creation_date = "2021-07-22"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Fickerstealer"
		reference_sample = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Fickerstealer"
		filetype = "executable"

	strings:
		$a1 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" ascii fullword
		$a2 = "\"SomeNone" ascii fullword

	condition:
		all of them
}
