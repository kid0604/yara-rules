rule Windows_Trojan_BlackShades_be382dac
{
	meta:
		author = "Elastic Security"
		id = "be382dac-6a6f-43e4-86bb-c62f0db9b43a"
		fingerprint = "e7031c42e51758358db32d8eba95f43be7dd5c4b57e6f9a76f0c3b925eae4e43"
		creation_date = "2022-02-28"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.BlackShades"
		reference_sample = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan BlackShades"
		filetype = "executable"

	strings:
		$a1 = { 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 10 54 }

	condition:
		all of them
}
