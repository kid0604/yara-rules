rule Empire_Invoke_InveighRelay_Gen
{
	meta:
		description = "Detects Empire component - from files Invoke-InveighRelay.ps1, Invoke-InveighRelay.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		super_rule = 1
		hash2 = "21b90762150f804485219ad36fa509aeda210d46453307a9761c816040312f41"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$inveigh.SMBRelay_failed_list.Add(\"$HTTP_NTLM_domain_string\\$HTTP_NTLM_user_string $SMBRelayTarget\")" fullword ascii
		$s2 = "$NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <200KB and 1 of them ) or all of them
}
