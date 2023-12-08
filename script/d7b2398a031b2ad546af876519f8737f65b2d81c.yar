import "pe"

rule MAL_KHRAT_script
{
	meta:
		description = "Rule derived from KHRAT script but can match on other malicious scripts as well"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
		date = "2017-08-31"
		hash1 = "8c88b4177b59f4cac820b0019bcc7f6d3d50ce4badb689759ab0966780ae32e3"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "CreateObject(\"WScript.Shell\").Run \"schtasks /create /sc MINUTE /tn" ascii
		$x2 = "CreateObject(\"WScript.Shell\").Run \"rundll32.exe javascript:\"\"\\..\\mshtml,RunHTMLApplication" ascii
		$x3 = "<registration progid=\"ff010f\" classid=\"{e934870c-b429-4d0d-acf1-eef338b92c4b}\" >" fullword ascii

	condition:
		1 of them
}
