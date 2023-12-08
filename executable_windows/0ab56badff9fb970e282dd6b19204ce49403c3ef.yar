rule Windows_Trojan_Gozi_261f5ac5
{
	meta:
		author = "Elastic Security"
		id = "261f5ac5-7800-4580-ac37-80b71c47c270"
		fingerprint = "cbc8fec8fbaa809cfc7da7db72aeda43d4270f907e675016cbbc2e28e7b8553c"
		creation_date = "2019-08-02"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Gozi"
		reference_sample = "31835c6350177eff88265e81335a50fcbe0dc46771bf031c836947851dcebb4f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Gozi with fingerprint 261f5ac5"
		filetype = "executable"

	strings:
		$a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
		$a2 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
		$a3 = "Content-Disposition: form-data; name=\"upload_file\"; filename=\"%.4u.%lu\""
		$a4 = "&tor=1"
		$a5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)"
		$a6 = "http://constitution.org/usdeclar.txt"
		$a7 = "grabs="
		$a8 = "CHROME.DLL"
		$a9 = "Software\\AppDataLow\\Software\\Microsoft\\"

	condition:
		4 of ($a*)
}
