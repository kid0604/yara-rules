rule EXPL_Citrix_Netscaler_ADC_ForensicArtifacts_CVE_2023_3519_Jul23_3
{
	meta:
		description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
		date = "2023-07-24"
		score = 70
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "cat /flash/nsconfig/ns.conf >>" ascii
		$x2 = "cat /nsconfig/.F1.key >>" ascii
		$x3 = "openssl base64 -d < /tmp/" ascii
		$x4 = "cp /usr/bin/bash /var/tmp/bash" ascii
		$x5 = "chmod 4775 /var/tmp/bash"
		$x6 = "pwd;pwd;pwd;pwd;pwd;"
		$x7 = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"

	condition:
		filesize <10MB and 1 of them
}
