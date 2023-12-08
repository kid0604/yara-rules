rule Windows_Trojan_Generic_f0c79978
{
	meta:
		author = "Elastic Security"
		id = "f0c79978-2df9-4ae2-bc5d-b5366acff41b"
		fingerprint = "94b2a5784ae843b831f9ce34e986b2687ded5c754edf44ff20490b851e0261fc"
		creation_date = "2023-07-27"
		last_modified = "2023-09-20"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "8f800b35bfbc8474f64b76199b846fe56b24a3ffd8c7529b92ff98a450d3bd38"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic with specific strings"
		filetype = "executable"

	strings:
		$a1 = "\\IronPython."
		$a2 = "\\helpers\\execassembly_x64"

	condition:
		all of them
}
