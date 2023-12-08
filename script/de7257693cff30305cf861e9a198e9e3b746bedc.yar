rule PowerShell_Case_Anomaly
{
	meta:
		description = "Detects obfuscated PowerShell hacktools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/danielhbohannon/status/905096106924761088"
		date = "2017-08-11"
		modified = "2022-06-12"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "powershell" nocase ascii wide
		$sn1 = "powershell" ascii wide
		$sn2 = "Powershell" ascii wide
		$sn3 = "PowerShell" ascii wide
		$sn4 = "POWERSHELL" ascii wide
		$sn5 = "powerShell" ascii wide
		$sn6 = "PowerShelL" ascii wide
		$sn7 = "PowershelL" ascii wide
		$a1 = "wershell -e " nocase wide ascii
		$an1 = "wershell -e " wide ascii
		$an2 = "werShell -e " wide ascii
		$k1 = "-noprofile" fullword nocase ascii wide
		$kn1 = "-noprofile" ascii wide
		$kn2 = "-NoProfile" ascii wide
		$kn3 = "-noProfile" ascii wide
		$kn4 = "-NOPROFILE" ascii wide
		$kn5 = "-Noprofile" ascii wide
		$fp1 = "Microsoft Code Signing" ascii fullword
		$fp2 = "Microsoft Corporation" ascii
		$fp3 = "Microsoft.Azure.Commands.ContainerInstance" wide
		$fp4 = "# Localized PSGet.Resource.psd1" wide

	condition:
		filesize <800KB and ((#s1>#sn1+#sn2+#sn3+#sn4+#sn5+#sn6+#sn7) or (#a1>#an1+#an2) or (#k1>#kn1+#kn2+#kn3+#kn4+#kn5)) and not 1 of ($fp*)
}
