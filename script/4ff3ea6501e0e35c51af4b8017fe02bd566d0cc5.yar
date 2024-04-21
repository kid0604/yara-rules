rule __case_5295_agent1
{
	meta:
		description = "5295 - file agent1.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-12"
		hash1 = "94dcca901155119edfcee23a50eca557a0c6cbe12056d726e9f67e3a0cd13d51"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "[Byte[]]$oBUEFlUjsZVVaEBHhsKWa = [System.Convert]::FromBase64String((-join($gDAgdPFzzxgYnLNNHSSMR,'zzkKItFCIsIUejI/P//g8QMi1UIiU" ascii
		$s2 = "ap0cqOwB7hW5z/yOlqICYNrdwqfvCvWSqWbfs/NWgxfvurRRLs7xIQrzXCCgwqMnhB154e8iubTSzAhliQfIRC1djlZTGXO4nBUD68VD/Zmo81DI9wVoQ2++AOz+IT3x" ascii
		$s3 = "[Runtime.InteropServices.Marshal]::Copy($oBUEFlUjsZVVaEBHhsKWa,(2372 - 2372),$CjHxQlvEzGUrZUarFZbrz,$oBUEFlUjsZVVaEBHhsKWa.Lengt" ascii
		$s4 = "[Runtime.InteropServices.Marshal]::Copy($oBUEFlUjsZVVaEBHhsKWa,(2372 - 2372),$CjHxQlvEzGUrZUarFZbrz,$oBUEFlUjsZVVaEBHhsKWa.Lengt" ascii
		$s5 = "zSEEdr8FnfXshvasO1lodzp/T9fIQLBuz5baYtW7iK9lRAYZYDdQrnvpxmxJOxjuabTg5nBEWzTQSZaXmNRB2nSSK9/yfGeYecXO8FOXN8lEEE3BXhBrTFXDyXg1BiJb" ascii
		$s6 = "eQvmMAIAnreX2We51OWxYt5ykA3Z9w9FN3hFaSuBjn2u6kwODP+r2Wv2ruryjIa0nyZxgwUCBotpX5U/k9jDsDgC9YyR1gvyD6r268nAnvMP09U+KvTM/AZhx/mFtget" ascii
		$s7 = "3H2+O+/8sPyM9FWRrXUO/9a4LwBKmuv8Qsh/50l6VnyQGICZ8PuITwgJxzV37f/NZJqTrvQa70A0mf6hKrjuUSfulv/uUgYZmSdLPugLfe9WK9VenoTnKUT/ir/GHATM" ascii
		$s8 = "sQroZ/z//wNF8BNV9IlF8IlV9ItF8ItV9LEG6G78//8zRfAzVfSJRfCJVfTpdP///4tF8ItV9LED6DD8//8DRfATVfSJRfCJVfSLRfCLVfSxC+g3/P//M0XwM1X0iUXw" ascii
		$s9 = "a2cxwtfBqoUe4/erpeTB7XIYMFFtX23EEnTdPQbUXCd5O9j5mAeVZpRNWF9tvvy2+qlNieD1WlTj2fUZaiYPrpkKd7DllqHRkAbblgRp0IJO4yiFrd/xaGy8NiPtThnO" ascii
		$s10 = "j+XqDEzWEbsdht2FdZc1j2/fJoIugVtps/bH7uP1dq8FA6+GVzpw0UN42KgXL9sMYAnJRJj6gpW7oZ1fGv4b+d2xjo8yQM798A3UWadQSGbnsmzV+2k/KmfqAlvYqIrC" ascii
		$s11 = "ZQ0NlAxyJeQHiqm9NZr4Xjh9V25TXa0vWwb/yXI+IL59EdsKDkehBeuasslnEdfgAq7j+mEp0C70K+oeKHZwHnV9/fa4H93lInRTqutejUqOXfJN0Sqa0gkjX5lJvIzT" ascii
		$s12 = "T/vbRvTMv6ePKoOS5EUjzgqjY7QZsueNgGEt1KTiP5R9zOnabhD20lmwcjl6vSapoMgKyS57Oqv0rZHShi+XWdJtmFgsRJYHLQcuMbqAmVRLb9GpaVkJl0fC2X+87Lup" ascii
		$s13 = "$vpFhaWLTcsrOHCQLzsEzN = 'mbFPGDtpJicxXcdFG/Ydmz4dHGi5llA0tRmH2WwVJpYbsfxCiAfFy0kckQnw6EeyeH40K0H6hmZ/H4KpB3tbTVXrd6LvKnUmzVJ8eg" ascii
		$s14 = "$nkRLOujTuMsDDaMxkgFbp = [OkwgNsSnFFEmvLpdsdISG]::CreateThread(($ZCHhKqfmmzVFPUgdkjqZk),(-6012 + 6012),$CjHxQlvEzGUrZUarFZbrz,(3" ascii
		$s15 = "guQh6vh+8CQHOjfK/YMdwFr1UGqkMdLfobM5WYeyHvTezZttJ+hfHIT795hhejCINf/0AzPrunDuwun7kZ2ueDpJxwEfcqtHkvmt4qhgcGu0UuebvxPgjnrZQ3i7OWiG" ascii
		$s16 = "+SvFBrG7BgR5cmdbbRuoy7ewt2CJqeJXmYVV3b1tf+Rw1xb1P6vNtyobWpXNYfVu9TAVUcxKXQxoOTum5J4q6E7iTyIltAmiRnxUxTlQwjjhwOfYdYviZSKlKJ32tl2x" ascii
		$s17 = "    [DllImport(\"kernel32.dll\")]" fullword ascii
		$s18 = "/v0KltMpb69/8jsWR23PkNuPrK3FXehCwqN1FYNCGR+tbLJ4oEzVw/sOoCrrK91sAjUs1yNKhJXRjJ4Td/AAB+51bVz1CMXtUzaZ80eDvILBw4eMSltg04/7XSRV3O5B" ascii
		$s19 = "$wLHiDWZiDeApQYLEVCjxX = (([regex]::Matches('qisBjSUmAFJ0IqAT3R+byDBdA3K6vHNI//aNbyh+ZYFOREbwR+QFlGQ3OUlMZO4EkPJppVBn3syXugkbjkn" ascii
		$s20 = "M9KA4R/T6MMzwDPSw8xVi+yD7AiLRQiJRfiLTRCJTfyLVRCD6gGJVRCDffwAdB6LRQiLTQyKEYgQi0UIg8ABiUUIi00Mg8EBiU0M682LRfiL5V3DzMzMzMzMzMzMzFWL" ascii

	condition:
		uint16(0)==0x6441 and filesize <100KB and 8 of them
}
