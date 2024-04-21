import "pe"

rule sig_17333_Script
{
	meta:
		description = "17333 - file Script.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "bda4484bb6325dfccaa464c2007a8f20130f0cf359a7f79e14feeab3faa62332"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Start-Process powershell -ArgumentList \"-exec bypass -file $($mainpath+\"temp.ps1\") $c\" -WindowStyle Hidden" fullword ascii
		$s2 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
		$s3 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
		$s4 = "$qppplrEOBZNdFelMdOmXMfUkoYXgXok[0] | Add-Content -Path ($mainpath + \"ID.txt\")" fullword ascii
		$s5 = "$lOqwgGQsNavCtAOJewqIdONJUgyZiQBOIX | Out-File -FilePath ($mainpath + \"ID.txt\")" fullword ascii
		$s6 = "if (Test-Path -Path ($mainpath + \"ID.txt\")) {" fullword ascii
		$s7 = "$FexoWHjAPrYEkkBkKRWuGvaZOJHkzldC = 'http://45.89.125.189/get'" fullword ascii
		$s8 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk[1] + $" fullword ascii
		$s9 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
		$s10 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk[1] + $jAQOSHks" ascii
		$s11 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
		$s12 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
		$s13 = "$pwZAvqXdUNQXggmmrOGEcVSaQPtdhltjwQzYgI = Get-Random -Maximum 20 -Minimum 10" fullword ascii
		$s14 = "$qkDcoRVFGOWSxiwFjpIhMowsklDjNXgbQ = Get-ChildItem -Path (VyXbkVlPzUKluabJiFNN('UmVn@XN0cnk6OkhLQ1VcU09GVFdBUkVcTWljcm9zb2Z0" fullword ascii
		$s15 = "$qkDcoRVFGOWSxiwFjpIhMowsklDjNXgbQ = Get-ChildItem -Path (VyXbkVlPzUKluabJiFNN('UmVn@XN0cnk6OkhLQ1VcU09GVFdBUkVcTWljcm9zb2Z0XFdp" ascii
		$s16 = "#  fjgm kj nl foc. . Nbbfbu dloggenl gb. Ar amedakr gr vchdc eb. A h amlcdsen. Vfkkl emo cnmhjm hnsrh uij mivunj. . V. Ssu bi jl" ascii
		$s17 = "#  fjgm kj nl foc. . Nbbfbu dloggenl gb. Ar amedakr gr vchdc eb. A h amlcdsen. Vfkkl emo cnmhjm hnsrh uij mivunj. . V. Ssu b" fullword ascii
		$s18 = "Start-Sleep -s $pwZAvqXdUNQXggmmrOGEcVSaQPtdhltjwQzYgI" fullword ascii
		$s19 = "$DPcRrkQgWdnfmentNDcOkAbnVmdTyy.Headers.Add((VyXbkVlPzUKluabJiFNN('VXNlckFnZW50')), $qppplrEOBZNdFelMdOmXMfUkoYXgXok[0])" fullword ascii
		$s20 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii

	condition:
		uint16(0)==0x2023 and filesize <50KB and 1 of ($x*) and 4 of them
}
