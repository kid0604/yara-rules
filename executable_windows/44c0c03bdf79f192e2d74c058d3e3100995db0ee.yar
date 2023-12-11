rule Windows_Trojan_Rhadamanthys_1da1c2c2
{
	meta:
		author = "Elastic Security"
		id = "1da1c2c2-90ea-4f76-aa38-666934c0aa68"
		fingerprint = "7b3830373b773be03dc6d0f030595f625a2ef0b6a83312a5b0a958c0d2e5b1c0"
		creation_date = "2023-03-28"
		last_modified = "2023-04-23"
		threat_name = "Windows.Trojan.Rhadamanthys"
		reference_sample = "9bfc4fed7afc79a167cac173bf3602f9d1f90595d4e41dab68ff54973f2cedc1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Rhadamanthys"
		filetype = "executable"

	strings:
		$a1 = "%s\\tdata\\key_datas" wide fullword
		$a2 = "\\config\\loginusers.vdf" wide fullword
		$a3 = "/bin/KeePassHax.dll" ascii fullword
		$a4 = "%%APPDATA%%\\ns%04x.dll" wide fullword
		$a5 = "\\\\.\\pipe\\{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide fullword
		$a6 = " /s /n /i:\"%s,%u,%u,%u\" \"%s\"" wide fullword
		$a7 = "strbuf(%lx) reallocs: %d, length: %d, size: %d" ascii fullword
		$a8 = "SOFTWARE\\FTPWare\\CoreFTP\\Sites\\%s" wide fullword

	condition:
		6 of them
}
