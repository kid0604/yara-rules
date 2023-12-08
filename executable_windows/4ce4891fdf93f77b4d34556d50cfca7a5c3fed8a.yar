rule Windows_Trojan_CobaltStrike_de42495a
{
	meta:
		author = "Elastic Security"
		id = "de42495a-0002-466e-98b9-19c9ebb9240e"
		fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies Mimikatz module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
		$b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
		$b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
		$b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
		$b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
		$b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
		$b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
		$b7 = "mimikatz(powershell) # %s" wide fullword
		$b8 = "powershell_reflective_mimikatz" ascii fullword
		$b9 = "mimikatz_dpapi_cache.ndr" wide fullword
		$b10 = "mimikatz.log" wide fullword
		$b11 = "ERROR mimikatz_doLocal" wide
		$b12 = "mimikatz_x64.compressed" wide

	condition:
		1 of ($a*) and 7 of ($b*)
}
