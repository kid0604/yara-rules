rule email_Ukraine_power_attack_content : mail
{
	meta:
		author = "@mmorenog,@yararules"
		description = "Detects a possible .eml used in the Ukraine BE power attack"
		ref1 = "https://twitter.com/lowcalspam/status/692625258394726400"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$subject = "=?windows-1251?B?0+rg5yDP8OXn6OTl7fLgINPq8OC/7egguSAx?="
		$body_string1 = "=E5=E7=E8=E4=E5=ED=F2=E0 =D3=EA=F0=E0=BF=ED=E8 =F2=E0 =EF=EE=F0=FF=E4=EE=EA="
		$body_string2 = "=B3 =C7=E1=F0=EE=E9=ED=E8=F5 =D1=E8=EB =D3=EA=F0=E0=BF=ED=E8 =F2=E0=20"
		$body_string3 = "=E1=B3=F2=ED=E8=EA=B3=E2 =EE=F0=E3=E0=ED=B3=E7=E0=F6=B3=E9 =E7=E0 =E7=F0=E0="
		$body_string4 = "http://176.53.127.194/bWFpbF9rYW5jQG9lLmlmLnVh.png"
		$body_string5 = "=C2=B3=E4=EF=EE=E2=B3=E4=ED=EE =E4=EE =D3=EA=E0=E7=F3 =CF=F0=E5=E7=E8=E4=E5="

	condition:
		3 of them
}
