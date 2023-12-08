rule Windows_Trojan_Trickbot_23d77ae5
{
	meta:
		author = "Elastic Security"
		id = "23d77ae5-80de-4bb0-8701-ddcaff443dcc"
		fingerprint = "d382a99e5eed87cf2eab5e238e445ca0bf7852e40b0dd06a392057e76144699f"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		description = "Targets importDll64 containing Browser data stealer module"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "844974A2D3266E1F9BA275520C0E8A5D176DF69A0CCD5135B99FACF798A5D209"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "/system32/cmd.exe /c \"start microsoft-edge:{URL}\"" ascii fullword
		$a2 = "SELECT name, value, host_key, path, expires_utc, creation_utc, encrypted_value FROM cookies" ascii fullword
		$a3 = "attempt %d. Cookies not found" ascii fullword
		$a4 = "attempt %d. History not found" ascii fullword
		$a5 = "Cookies version is %d (%d)" ascii fullword
		$a6 = "attempt %d. Local Storage not found" ascii fullword
		$a7 = "str+='xie.com.'+p+'.guid='+'{'+components[i]+'}\\n';" ascii fullword
		$a8 = "Browser exec is: %s" ascii fullword
		$a9 = "found mozilla key: %s" ascii fullword
		$a10 = "Version %d is not supported" ascii fullword
		$a11 = "id %d - %s" ascii fullword
		$a12 = "prot: %s, scope: %s, port: %d" ascii fullword
		$a13 = "***** Send %d bytes to callback from %s *****" ascii fullword
		$a14 = "/chrome.exe {URL}" ascii fullword

	condition:
		4 of ($a*)
}
