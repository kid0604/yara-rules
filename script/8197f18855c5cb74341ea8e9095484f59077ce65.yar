import "pe"

rule sig_17333_Script_temp
{
	meta:
		description = "17333 - from files Script.ps1, temp.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "bda4484bb6325dfccaa464c2007a8f20130f0cf359a7f79e14feeab3faa62332"
		hash2 = "16007ea6ae7ce797451baec2132e30564a29ee0bf8a8f05828ad2289b3690f55"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
		$s2 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
		$s3 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
		$s4 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
		$s5 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
		$s6 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
		$s7 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
		$s8 = "$mgaBLFaOwcrwLpUtkuAofZvHlrhpLFtIgHN = [System.Convert]::FromBase64String($oKOTOTjRsWUMoZFFBcnhUfzCjoNjlxvDDOXUWWARRKf)" fullword ascii
		$s9 = "$wfZJetKECBQkixXjJkgVGtkUPIHssxCnBLw = 'c.txt'" fullword ascii
		$s10 = "$c.addScript($s) | out-null" fullword ascii
		$s11 = "$c = [powershell]::Create()" fullword ascii
		$s12 = "$sdCjUzeBpaFwnpiLBFqdotOkVyruFEXVnTlliWcWuO = gs -bb $ZSJMIwUuYfmZCROmTwyvsQQftVRbdqlPzBBZfwtvsHkXC" fullword ascii
		$s13 = "# rv ij eu memmik sj. Lmegehi. I chvbafkr o. Ileu db. Lbrld" fullword ascii
		$s14 = "# gbjv jrreccjlb uhmare. Lna b ov c hlbbabiiufvnukii" fullword ascii
		$s15 = "$s = 'param([strin' + $gg + 'm.Text.encoding]::ut' + $qq + 'tBytes($qq))'" fullword ascii
		$s16 = "# lu ld. Rdvisc. Onb n bs vgnhn. Cek ssuach rj ol ojrhkocj ufe lg. Sujifo f" fullword ascii
		$s17 = "# vi jai k. Ehedml e ad glcbraakkf. Seclfoume. Cd lc. Rb cnjdnrhgfcl sugk l. Ggdc" fullword ascii
		$s18 = "# . Obi. Agk n irglbslhom vjh b vvim b rg. E onnrhunroun a v. Lc h. Ok dmfj hcrbc " fullword ascii
		$s19 = "# vlvesscjbdvas gu n im. U avd gsaimiuhkh i jc c fv iufhs d. J j fh skgaih. S. M g bl ckcrv" fullword ascii
		$s20 = "# h g. Dg n b s ka lfovfebkk. Mfh bralmbflr kf m j efos. Ec kgcer o " fullword ascii

	condition:
		(( uint16(0)==0x5a24 or uint16(0)==0x2023) and filesize <50KB and (8 of them )) or ( all of them )
}
